// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tropic Square's TROPIC01 model (`model_server`, ts-tvl) as the chip under the anchor: one server
//! process per test, reached over its TCP protocol as an SPI device.
//!
//! `DSM_TROPIC01_MODEL_SERVER` names the server and `DSM_TROPIC01_MODEL_CFG` its chip configuration;
//! `ci/tropic01_model.sh` installs both, each checked against its pinned digest. A test with neither
//! fails: nothing here passes without the model.
//!
//! The model is the vendor's behavioural reference. It enforces access privileges, latches them at a
//! reboot and keeps R-memory as the chip does, one command at a time. It does not model timing or
//! tear a write. Its factory configuration here is the one Tropic Square's catalog list gives for a
//! production part.

use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::time::Duration;

use anchor_chip::bring_up::{bring_up, serve_measured, BoardAnchor, BringUpFailure, Measurement};
use anchor_chip::session::ChipFault;
use anchor_chip::{Board, UntestedRandomness};
use anchor_core::enrollment::Provisioning;
use anchor_core::proto::{decode_response, encode_request, pb};
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::{Error, ErrorKind, ErrorType, Operation, SpiDevice};
use tropic01::Tropic01;

const TAG_CSN_LOW: u8 = 0x01;
const TAG_CSN_HIGH: u8 = 0x02;
const TAG_SPI_SEND: u8 = 0x03;
const TAG_POWER_ON: u8 = 0x04;
const TAG_POWER_OFF: u8 = 0x05;
/// The L2 byte that asks the chip for its response.
const L2_GET_RESPONSE: u8 = 0xAA;
/// The L2 request that reboots the chip.
const L2_STARTUP_REQ: u8 = 0xB3;
/// The L2 status of a request the chip took.
const L2_REQ_OK: u8 = 0x01;
/// The commands that change what the chip stores, as the model logs them. Everything else leaves its
/// memory as it was, so a power cut after it leaves the same chip as a cut before it.
const STORING_COMMANDS: [&str; 13] = [
    "ts_l3_r_mem_data_write",
    "ts_l3_r_mem_data_erase",
    "ts_l3_mcounter_init",
    "ts_l3_mcounter_update",
    "ts_l3_ecc_key_generate",
    "ts_l3_ecc_key_store",
    "ts_l3_ecc_key_erase",
    "ts_l3_pairing_key_write",
    "ts_l3_pairing_key_invalidate",
    "ts_l3_i_config_write",
    "ts_l3_r_config_write",
    "ts_l3_r_config_erase",
    "ts_l3_mac_and_destroy",
];

/// What Tropic Square programs into its T2XX and T3XX parts at manufacturing (catalog list v2.0,
/// section 5): sensors on in R-config, and in I-config the PTRNG and firmware tests on.
pub(crate) const PRODUCTION_FACTORY: &str =
    "i_config:\n  cfg_start_up: 0xFFFFFFF9\n  cfg_debug: 0xFFFFFFFE\n\
                                  r_config:\n  cfg_sensors: 0xFFFC0000\n";

/// The board's sealed secret in these runs.
pub const SEALED: [u8; 32] = [0x5A; 32];

fn required_env(name: &str) -> PathBuf {
    match std::env::var_os(name) {
        Some(value) => PathBuf::from(value),
        None => panic!("{name} is not set: run ci/tropic01_model.sh, which installs the model"),
    }
}

/// The transport to the chip failed: the power was cut, or the model went away.
#[derive(Debug)]
pub struct SpiCut;

impl Error for SpiCut {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

/// How many SPI transactions the power lasts.
#[derive(Default)]
pub struct Power {
    pub(crate) budget: Cell<Option<u64>>,
    pub(crate) spent: Cell<u64>,
    /// The model's log, when this server keeps one, and how far it has been read.
    log: RefCell<Option<(std::fs::File, String)>>,
    /// The transactions in which the chip ran a command that changes what it stores.
    pub(crate) stores: RefCell<Vec<u64>>,
    /// Corrupt the CRC of the answer to the next reboot, as OI_TR01_ERR_2025091800 describes.
    pub(crate) garble_reboot_crc: Cell<Garble>,
    reboot_asked: Cell<Garble>,
}

/// Whether a reboot's answer has its CRC corrupted.
#[derive(Clone, Copy, PartialEq)]
pub struct Garble(pub(crate) u8);

impl Default for Garble {
    fn default() -> Self {
        Self::NO
    }
}

impl Garble {
    pub(crate) const NO: Self = Self(0);
    pub(crate) const YES: Self = Self(1);
}

impl Power {
    /// Note whether the transaction that just went through ran a command that stores.
    fn watch_log(&self) {
        let mut log = self.log.borrow_mut();
        let Some((file, text)) = log.as_mut() else {
            return;
        };
        text.clear();
        if let Err(e) = file.read_to_string(text) {
            panic!("the model's log did not read: {e}");
        }
        if text.lines().any(|line| {
            line.contains("Executing") && STORING_COMMANDS.iter().any(|c| line.contains(c))
        }) {
            self.stores.borrow_mut().push(self.spent.get());
        }
    }

    fn spend(&self) -> Result<(), SpiCut> {
        match self.budget.get() {
            Some(0) => return Err(SpiCut),
            Some(left) => self.budget.set(Some(left - 1)),
            None => {}
        }
        self.spent.set(self.spent.get() + 1);
        Ok(())
    }
}

pub(crate) fn call(stream: &mut TcpStream, tag: u8, payload: &[u8]) -> Vec<u8> {
    let length = match u16::try_from(payload.len()) {
        Ok(length) => length,
        Err(e) => panic!("an SPI frame fits the model's protocol: {e}"),
    };
    let mut frame = Vec::with_capacity(3 + payload.len());
    frame.push(tag);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(payload);
    if let Err(e) = stream.write_all(&frame) {
        panic!("the model took no frame: {e}");
    }
    let mut header = [0u8; 3];
    if let Err(e) = stream.read_exact(&mut header) {
        panic!("the model answered nothing: {e}");
    }
    assert_eq!(header[0], tag, "the model answered another tag");
    let mut answer = vec![0u8; usize::from(u16::from_le_bytes([header[1], header[2]]))];
    if let Err(e) = stream.read_exact(&mut answer) {
        panic!("the model's answer was cut short: {e}");
    }
    answer
}

/// The chip's SPI bus, over the model's protocol.
pub struct ModelSpi {
    stream: Rc<RefCell<TcpStream>>,
    power: Rc<Power>,
}

impl ModelSpi {
    /// One SPI transfer. The driver clocks its whole buffer; the chip reads a request only as far as
    /// its length field says, and the model parses exactly that frame.
    fn exchange(&mut self, buffer: &mut [u8]) {
        let clocked = if buffer[0] == L2_GET_RESPONSE {
            buffer.len()
        } else {
            (2 + usize::from(buffer[1]) + 2).min(buffer.len())
        };
        let miso = call(
            &mut self.stream.borrow_mut(),
            TAG_SPI_SEND,
            &buffer[..clocked],
        );
        let asked = buffer[0];
        buffer.fill(0);
        buffer[..miso.len()].copy_from_slice(&miso);
        if asked == L2_STARTUP_REQ {
            self.power
                .reboot_asked
                .set(self.power.garble_reboot_crc.get());
        } else if asked == L2_GET_RESPONSE
            && self.power.reboot_asked.get() == Garble::YES
            && buffer[1] == L2_REQ_OK
        {
            // CHIP_STATUS, STATUS, RSP_LEN, the data, then the CRC.
            buffer[3 + usize::from(buffer[2]) + 1] ^= 0xFF;
            self.power.reboot_asked.set(Garble::NO);
        }
    }
}

/// The chip-select line, which the driver drives around each transaction.
pub struct ModelCsn {
    stream: Rc<RefCell<TcpStream>>,
}

impl embedded_hal::digital::ErrorType for ModelCsn {
    type Error = Infallible;
}

impl OutputPin for ModelCsn {
    fn set_low(&mut self) -> Result<(), Infallible> {
        call(&mut self.stream.borrow_mut(), TAG_CSN_LOW, &[]);
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Infallible> {
        call(&mut self.stream.borrow_mut(), TAG_CSN_HIGH, &[]);
        Ok(())
    }
}

impl ErrorType for ModelSpi {
    type Error = SpiCut;
}

impl SpiDevice for ModelSpi {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), SpiCut> {
        for operation in operations {
            match operation {
                Operation::TransferInPlace(buffer) => {
                    self.power.spend()?;
                    self.exchange(buffer);
                    self.power.watch_log();
                }
                Operation::DelayNs(_) => {}
                Operation::Read(_) | Operation::Write(_) | Operation::Transfer(_, _) => {
                    panic!("the driver clocks the chip only with TransferInPlace")
                }
            }
        }
        Ok(())
    }
}

/// The board in these runs: the operating system's entropy, and no wait.
pub struct HostBoard;

impl Board for HostBoard {
    fn random_key(&self) -> Option<[u8; 32]> {
        let mut key = Vec::with_capacity(32);
        match std::fs::File::open("/dev/urandom").and_then(|f| f.take(32).read_to_end(&mut key)) {
            Ok(_read) => match <[u8; 32]>::try_from(key) {
                Ok(key) => Some(key),
                Err(short) => panic!("no entropy: {} bytes", short.len()),
            },
            Err(e) => panic!("no entropy: {e}"),
        }
    }
    fn wait_100ms(&self) {}
    fn alive(&self) {}
    fn silicon_revision(&self) -> u8 {
        anchor_chip::MIN_SILICON_REVISION
    }
}

pub type ModelChip = Tropic01<ModelSpi, ModelCsn>;
pub type BringUpError = BringUpFailure<ChipFault<ModelSpi, ModelCsn>>;

/// One TROPIC01 model in its own server process.
pub struct ModelServer {
    child: Child,
    port: u16,
    workdir: PathBuf,
    pub power: Rc<Power>,
}

impl ModelServer {
    pub fn start() -> Self {
        Self::launch(PRODUCTION_FACTORY, None)
    }

    /// A chip with this factory configuration, and a log of what it runs if `log` names a file.
    pub(crate) fn launch(factory: &str, log: Option<&str>) -> Self {
        let server = required_env("DSM_TROPIC01_MODEL_SERVER");
        let vendor_configuration = required_env("DSM_TROPIC01_MODEL_CFG");
        let port = match TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()) {
            Ok(address) => address.port(),
            Err(e) => panic!("no free port: {e}"),
        };
        let workdir = std::env::temp_dir().join(format!("dsm-tropic01-model-{port}"));
        if let Err(e) = std::fs::create_dir_all(&workdir) {
            panic!("no working directory for the model: {e}");
        }
        // Tropic Square's chip configuration, with the factory's settings for this part added.
        let mut chip = match std::fs::read_to_string(&vendor_configuration) {
            Ok(text) => text,
            Err(e) => panic!("{}: {e}", vendor_configuration.display()),
        };
        chip.push_str(factory);
        let configuration = workdir.join("chip.yml");
        if let Err(e) = std::fs::write(&configuration, chip) {
            panic!("the chip's configuration was not written: {e}");
        }
        let mut command = Command::new(&server);
        command
            .arg("tcp")
            .args(["-p", &port.to_string()])
            .arg("-c")
            .arg(&configuration)
            .arg("-o")
            .arg(workdir.join("model_out.yml"));
        let power = Rc::new(Power::default());
        if let Some(log) = log {
            let log = workdir.join(log);
            let logging = workdir.join("logging.yml");
            let text = format!(
                "version: 1\nformatters:\n  plain:\n    format: '%(message)s'\n\
                 handlers:\n  file:\n    class: logging.FileHandler\n    filename: {}\n    \
                 formatter: plain\nloggers:\n  model:\n    level: DEBUG\n    handlers:\n    - file\n",
                log.display()
            );
            if let Err(e) = std::fs::write(&logging, text) {
                panic!("the logging configuration was not written: {e}");
            }
            if let Err(e) = std::fs::write(&log, "") {
                panic!("the log was not started: {e}");
            }
            match std::fs::File::open(&log) {
                Ok(file) => *power.log.borrow_mut() = Some((file, String::new())),
                Err(e) => panic!("the log did not open: {e}"),
            }
            command.arg("--logging-configuration").arg(&logging);
        }
        let child = command
            .current_dir(&workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(e) => panic!("{} did not start: {e}", server.display()),
        };
        Self {
            child,
            port,
            workdir,
            power,
        }
    }

    pub(crate) fn connect(&self) -> TcpStream {
        for _attempt in 0..600 {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", self.port)) {
                return stream;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the model never listened on port {}", self.port);
    }

    /// Cut the power and restore it: the chip's session and SPI state go, its memory stays.
    pub fn power_cycle(&self) -> ModelChip {
        let mut stream = self.connect();
        call(&mut stream, TAG_POWER_OFF, &[]);
        call(&mut stream, TAG_POWER_ON, &[]);
        let stream = Rc::new(RefCell::new(stream));
        let chip = Tropic01::new(ModelSpi {
            stream: stream.clone(),
            power: self.power.clone(),
        })
        .with_cs_pin(ModelCsn { stream });
        match chip {
            Ok(chip) => chip,
            Err(e) => panic!("the chip-select line did not take: {e:?}"),
        }
    }

    /// Boot the anchor: what the production image does at reset, on the same code.
    pub fn boot(&self) -> Result<BoardAnchor, BringUpError> {
        bring_up(
            self.power_cycle(),
            &SEALED,
            HostBoard,
            UntestedRandomness::Refuse,
        )
    }
}

impl Drop for ModelServer {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("the model could not be stopped: {e}");
        }
        if let Err(e) = self.child.wait() {
            eprintln!("the model could not be reaped: {e}");
        }
        if let Err(e) = std::fs::remove_dir_all(&self.workdir) {
            eprintln!("the model's working directory stays: {e}");
        }
    }
}

/// An anchor, answered one frame at a time as the monitor's handler answers.
pub struct Served(Option<BoardAnchor>);

impl Served {
    pub fn new(anchor: BoardAnchor) -> Self {
        Self(Some(anchor))
    }

    pub fn request(&mut self, request: &pb::ApplianceRequest) -> pb::ApplianceResponse {
        self.measured(request, Measurement::Matches)
    }

    /// Answer a request under a measurement of the Non-secure image.
    pub fn measured(
        &mut self,
        request: &pb::ApplianceRequest,
        measurement: Measurement,
    ) -> pb::ApplianceResponse {
        let anchor = match self.0.take() {
            Some(anchor) => anchor,
            None => panic!("the anchor is held here between requests"),
        };
        let (anchor, answer) = serve_measured(anchor, &encode_request(request), measurement);
        self.0 = Some(anchor);
        match decode_response(&answer) {
            Ok(response) => response,
            Err(e) => panic!("the anchor answered no response: {e:?}"),
        }
    }

    pub fn bare(&mut self, op: pb::Op) -> pb::ApplianceResponse {
        self.request(&pb::ApplianceRequest {
            op: op as i32,
            ..Default::default()
        })
    }
}

/// What the owner's device provisions the anchor with.
pub fn provisioning() -> Provisioning {
    Provisioning {
        device_id: [0x77; 32],
        online_id_pk: vec![0x66; 64],
        policy_hash: [0x33; 32],
        genesis_root: [0x11; 32],
    }
}

/// A try-run of the install [`provision_request`] asks for.
pub fn try_run_request() -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: pb::Op::TryRun as i32,
        ..provision_request()
    }
}

pub fn provision_request() -> pb::ApplianceRequest {
    let provisioning = provisioning();
    pb::ApplianceRequest {
        op: pb::Op::Provision as i32,
        provision: Some(pb::Provisioning {
            device_id: provisioning.device_id.to_vec(),
            online_id_pk: provisioning.online_id_pk,
            policy_hash: provisioning.policy_hash.to_vec(),
            genesis_root: provisioning.genesis_root.to_vec(),
        }),
        ..Default::default()
    }
}
