// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Pico 2 W's radio, a CYW43439, on its gSPI bus: WL_ON on GPIO 23, one data line on GPIO 24,
//! chip select on GPIO 25, the clock on GPIO 29. PIO0's state machine 0 clocks the bits with the
//! pico-sdk's gSPI program; the core moves every word through the PIO FIFOs itself. No DMA: the
//! Non-secure side has none (the monitor's `boundary` says why), and Bluetooth needs none.
//!
//! The two pins the program does not drive, WL_ON and chip select, are driven through IO_BANK0's
//! output overrides: the Non-secure side has no SIO. The radio's firmware is read in place from
//! this image's flash region (`radio/`, Infineon's permissive binary license beside it).

use core::convert::Infallible;
use core::sync::atomic::{AtomicU32, Ordering};

use cyw43::SpiBusCyw43;
use embassy_futures::yield_now;
use embedded_hal::digital::{ErrorType, OutputPin};
use hal::pac;
use hal::pio::PIOExt;
use rp235x_hal as hal;

/// Where the radio's bring-up stands, for a debug probe to read (`nm` gives the address). Not an
/// authority signal: a boot-liveness probe for the bench, as the monitor's heartbeat is.
#[no_mangle]
pub static DSM_RADIO_STAGE: AtomicU32 = AtomicU32::new(0);

/// The stages [`DSM_RADIO_STAGE`] names.
pub mod stage {
    /// The pins and PIO are set; the radio is still held off.
    pub const PINS_SET: u32 = 1;
    /// The radio is being powered and its firmware loaded.
    pub const LOADING_FIRMWARE: u32 = 2;
    /// The radio answered and runs its firmware.
    pub const RADIO_UP: u32 = 3;
    /// The radio's control channel is initialised (country table loaded).
    pub const CONTROL_READY: u32 = 4;
    /// The Secure side gave the Bluetooth address its bytes.
    pub const ENTROPY_TAKEN: u32 = 5;
    /// The Bluetooth host is built and about to advertise.
    pub const HOST_BUILT: u32 = 6;
    /// Advertising; waiting for a wallet.
    pub const ADVERTISING: u32 = 7;
    /// A wallet is connected.
    pub const CONNECTED: u32 = 8;
    /// The Secure side refused the entropy: the radio stays dark.
    pub const ENTROPY_REFUSED: u32 = 20;
    /// The attribute table did not build.
    pub const HOST_NOT_BUILT: u32 = 21;
    /// The controller refused to advertise or accept; trying again.
    pub const ADVERTISE_REFUSED: u32 = 22;
}

/// Record where the radio's bring-up stands.
pub fn at(stage: u32) {
    DSM_RADIO_STAGE.store(stage, Ordering::Relaxed);
}

/// Bus commands written to the radio so far, for the probe.
#[no_mangle]
pub static DSM_RADIO_WRITES: AtomicU32 = AtomicU32::new(0);
/// Bus reads from the radio so far, for the probe.
#[no_mangle]
pub static DSM_RADIO_READS: AtomicU32 = AtomicU32::new(0);
/// The status word the radio answered the last command with, for the probe.
#[no_mangle]
pub static DSM_RADIO_LAST_STATUS: AtomicU32 = AtomicU32::new(0);
/// The last word a read brought back, for the probe.
#[no_mangle]
pub static DSM_RADIO_LAST_WORD: AtomicU32 = AtomicU32::new(0);

const PIN_WL_ON: u8 = 23;
const PIN_DATA: u8 = 24;
const PIN_CS: u8 = 25;
const PIN_CLK: u8 = 29;

/// `pull noblock`: the OSR takes the TX FIFO's word (or keeps what it holds).
const PULL_NOBLOCK: u16 = 0x8080;
/// `out x, 32`: X takes the OSR.
const OUT_X_32: u16 = 0x6020;
/// `out y, 32`: Y takes the OSR.
const OUT_Y_32: u16 = 0x6040;
/// `set pindirs, 1`: the SET pin becomes an output.
const SET_PINDIRS_OUT: u16 = 0xE081;
/// `set pins, 0`: the SET pin goes low.
const SET_PINS_LOW: u16 = 0xE000;
/// `jmp <addr>`: the program counter.
const JMP: u16 = 0x0000;

/// The PIO clock divider: 150 MHz / 3 = 50 MHz, a 25 MHz gSPI clock, inside the radio's 50 MHz
/// limit with the program written for that speed.
const CLOCK_DIVIDER_INT: u16 = 3;

/// A pin driven through IO_BANK0's output override, never SIO.
pub struct OverridePin(u8);

impl OverridePin {
    fn ctrl(&self) -> &pac::io_bank0::gpio::GPIO_CTRL {
        let io = unsafe { &*pac::IO_BANK0::ptr() };
        io.gpio(usize::from(self.0)).gpio_ctrl()
    }

    fn high(&self) {
        self.ctrl().modify(|_, w| w.outover().high());
    }

    fn low(&self) {
        self.ctrl().modify(|_, w| w.outover().low());
    }
}

impl ErrorType for OverridePin {
    type Error = Infallible;
}

impl OutputPin for OverridePin {
    fn set_low(&mut self) -> Result<(), Infallible> {
        self.low();
        Ok(())
    }

    fn set_high(&mut self) -> Result<(), Infallible> {
        self.high();
        Ok(())
    }
}

/// The gSPI bus on PIO0 SM0, chip select on its own pin.
pub struct PioGspi {
    cs: OverridePin,
    wrap_target: u8,
}

fn pio() -> &'static pac::pio0::RegisterBlock {
    unsafe { &*pac::PIO0::ptr() }
}

/// Prepare one pad as an output the override drives: isolation off, output enabled, held low.
fn output_pad(pin: u8) -> OverridePin {
    let io = unsafe { &*pac::IO_BANK0::ptr() };
    let pads = unsafe { &*pac::PADS_BANK0::ptr() };
    pads.gpio(usize::from(pin)).write(|w| {
        w.od().clear_bit();
        w.ie().clear_bit();
        w.pue().clear_bit();
        w.pde().clear_bit();
        w.drive()._4m_a();
        w.iso().clear_bit()
    });
    io.gpio(usize::from(pin)).gpio_ctrl().write(|w| {
        w.funcsel().null();
        w.oeover().enable();
        w.outover().low()
    });
    OverridePin(pin)
}

/// Hand a pad to PIO0: fast and strong, isolation off; the data line reads back through a Schmitt
/// trigger with the input synchroniser bypassed, as the radio's timing needs.
fn pio_pad(pin: u8, input: Input) {
    let io = unsafe { &*pac::IO_BANK0::ptr() };
    let pads = unsafe { &*pac::PADS_BANK0::ptr() };
    pads.gpio(usize::from(pin)).write(|w| {
        w.od().clear_bit();
        match input {
            Input::Read => w.ie().set_bit(),
            Input::Never => w.ie().clear_bit(),
        };
        w.pue().clear_bit();
        w.pde().clear_bit();
        w.schmitt().set_bit();
        w.slewfast().set_bit();
        w.drive()._12m_a();
        w.iso().clear_bit()
    });
    io.gpio(usize::from(pin))
        .gpio_ctrl()
        .write(|w| w.funcsel().pio0());
}

enum Input {
    Read,
    Never,
}

/// Run one instruction on SM0 (stopped or running).
fn exec(instr: u16) {
    pio()
        .sm(0)
        .sm_instr()
        .write(|w| unsafe { w.bits(u32::from(instr)) });
}

/// Stop SM0: its program counter and scratch registers can then be set with `exec`.
fn sm_stop() {
    pio()
        .ctrl()
        .modify(|r, w| unsafe { w.sm_enable().bits(r.sm_enable().bits() & !1) });
}

/// Start SM0 from where its program counter points.
fn sm_start() {
    pio()
        .ctrl()
        .modify(|r, w| unsafe { w.sm_enable().bits(r.sm_enable().bits() | 1) });
}

/// Bring the radio's pins and PIO0 SM0 up, the radio held off. Before the first gateway crossing:
/// `split` releases PIO0's reset through RESETS, which the Non-secure side holds only until then.
pub fn setup(pio0: pac::PIO0, resets: &mut pac::RESETS) -> (PioGspi, OverridePin) {
    // The pico-sdk's gSPI program for a PIO clock under 75 MHz: write X+1 bits out, turn the data
    // line around, read Y+1 bits in, then wait for the radio's event line and raise IRQ 0.
    let program = pio_proc::pio_asm!(
        ".side_set 1",
        ".wrap_target",
        "lp:",
        "out pins, 1    side 0",
        "jmp x-- lp     side 1",
        "set pindirs, 0 side 0",
        "nop            side 0",
        "lp2:",
        "in pins, 1     side 1",
        "jmp y-- lp2    side 0",
        "wait 1 pin 0   side 0",
        "irq 0          side 0",
        ".wrap",
    );
    let (mut pio_block, _sm0, _sm1, _sm2, _sm3) = pio0.split(resets);
    let installed = match pio_block.install(&program.program) {
        Ok(installed) => installed,
        Err(_no_room) => {
            // An empty instruction memory always has room for one program; a refusal here is a
            // broken PIO block, and the board halts rather than serve without its radio.
            loop {
                cortex_m::asm::wfi();
            }
        }
    };
    let offset = installed.offset();
    let wrap_target = installed.wrap_target();
    let wrap_source = offset + program.program.wrap.source;

    let pwr = output_pad(PIN_WL_ON);
    let cs = output_pad(PIN_CS);
    cs.high();
    pio_pad(PIN_DATA, Input::Read);
    pio_pad(PIN_CLK, Input::Never);

    let p = pio();
    p.input_sync_bypass()
        .modify(|r, w| unsafe { w.bits(r.bits() | (1 << PIN_DATA)) });
    let sm = p.sm(0);
    sm_stop();
    sm.sm_clkdiv()
        .write(|w| unsafe { w.int().bits(CLOCK_DIVIDER_INT).frac().bits(0) });
    sm.sm_execctrl().write(|w| unsafe {
        w.wrap_top()
            .bits(wrap_source)
            .wrap_bottom()
            .bits(wrap_target)
    });
    // Both shift registers move left: the radio takes and gives its bits most significant first.
    // The register's reset value shifts right; every field is set here.
    sm.sm_shiftctrl().write(|w| unsafe {
        w.autopull().set_bit();
        w.autopush().set_bit();
        w.pull_thresh().bits(0);
        w.push_thresh().bits(0);
        w.in_shiftdir().clear_bit();
        w.out_shiftdir().clear_bit()
    });
    // Both pins start as outputs held low: the clock through the SET group for a moment, then the
    // data line, which the SET group keeps.
    sm.sm_pinctrl()
        .write(|w| unsafe { w.set_base().bits(PIN_CLK).set_count().bits(1) });
    exec(SET_PINDIRS_OUT);
    exec(SET_PINS_LOW);
    sm.sm_pinctrl().write(|w| unsafe {
        w.out_base().bits(PIN_DATA).out_count().bits(1);
        w.set_base().bits(PIN_DATA).set_count().bits(1);
        w.in_base().bits(PIN_DATA);
        w.sideset_base().bits(PIN_CLK).sideset_count().bits(1)
    });
    exec(SET_PINDIRS_OUT);
    exec(SET_PINS_LOW);

    at(stage::PINS_SET);
    (PioGspi { cs, wrap_target }, pwr)
}

impl PioGspi {
    /// Load a scratch register from a word: the word goes through the TX FIFO into the OSR, and
    /// `out` moves it on. SM0 is stopped meanwhile.
    fn load(&self, out_instr: u16, value: u32) {
        pio().txf(0).write(|w| unsafe { w.bits(value) });
        exec(PULL_NOBLOCK);
        exec(out_instr);
    }

    /// Point the program at a transfer of `write_bits` out and `read_bits` in, the data line an
    /// output, and start it.
    fn begin(&self, write_bits: u32, read_bits: u32) {
        sm_stop();
        self.load(OUT_X_32, write_bits);
        self.load(OUT_Y_32, read_bits);
        exec(SET_PINDIRS_OUT);
        exec(JMP | u16::from(self.wrap_target));
        sm_start();
    }

    async fn push(&self, word: u32) {
        while (pio().fstat().read().txfull().bits() & 1) != 0 {
            yield_now().await;
        }
        pio().txf(0).write(|w| unsafe { w.bits(word) });
    }

    async fn pull(&self) -> u32 {
        while (pio().fstat().read().rxempty().bits() & 1) != 0 {
            yield_now().await;
        }
        pio().rxf(0).read().bits()
    }
}

impl SpiBusCyw43 for PioGspi {
    async fn cmd_write(&mut self, write: &[u32]) -> u32 {
        self.cs.low();
        let write_bits = (write.len() * 32 - 1) as u32;
        self.begin(write_bits, 31);
        for &word in write {
            self.push(word).await;
        }
        let status = self.pull().await;
        self.cs.high();
        DSM_RADIO_WRITES.fetch_add(1, Ordering::Relaxed);
        DSM_RADIO_LAST_STATUS.store(status, Ordering::Relaxed);
        status
    }

    async fn cmd_read(&mut self, write: u32, read: &mut [u32]) -> u32 {
        self.cs.low();
        let read_bits = (read.len() * 32 + 32 - 1) as u32;
        self.begin(31, read_bits);
        self.push(write).await;
        for word in read.iter_mut() {
            *word = self.pull().await;
            DSM_RADIO_LAST_WORD.store(*word, Ordering::Relaxed);
        }
        let status = self.pull().await;
        self.cs.high();
        DSM_RADIO_READS.fetch_add(1, Ordering::Relaxed);
        DSM_RADIO_LAST_STATUS.store(status, Ordering::Relaxed);
        status
    }

    async fn wait_for_event(&mut self) {
        while (pio().irq().read().bits() & 1) == 0 {
            yield_now().await;
        }
        pio().irq().write(|w| unsafe { w.bits(1) });
    }
}

/// The radio brought up on its bus and its firmware: its Bluetooth controller, its control handle
/// (whose `init` runs once the runner is spawned) and the runner that drives the bus.
pub async fn bring_up(
    spi: PioGspi,
    pwr: OverridePin,
) -> (
    cyw43::bluetooth::BtDriver<'static>,
    cyw43::Control<'static>,
    cyw43::Runner<'static, cyw43::SpiBus<OverridePin, PioGspi>>,
) {
    static STATE: static_cell::StaticCell<cyw43::State> = static_cell::StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let firmware = cyw43::aligned_bytes!("../radio/43439A0.bin");
    let bluetooth_firmware = cyw43::aligned_bytes!("../radio/43439A0_btfw.bin");
    let nvram = cyw43::aligned_bytes!("../radio/nvram_rp2040.bin");
    at(stage::LOADING_FIRMWARE);
    let (_net, bt, control, runner) =
        cyw43::new_with_bluetooth(state, pwr, spi, firmware, bluetooth_firmware, nvram).await;
    at(stage::RADIO_UP);
    (bt, control, runner)
}

/// The country and regulatory table the radio's `init` takes.
pub fn clm() -> &'static [u8] {
    include_bytes!("../radio/43439A0_clm.bin")
}
