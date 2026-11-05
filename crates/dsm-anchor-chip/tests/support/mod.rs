// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tropic Square's TROPIC01 model (`model_server`, ts-tvl) as the chip under the anchor: one server
//! process per test, reached over its TCP protocol as an SPI device.
//!
//! `DSM_TROPIC01_MODEL_SERVER` names the server and `DSM_TROPIC01_MODEL_CFG` its chip configuration;
//! `ci/tropic01_model.sh` installs both, each checked against its pinned digest. A test with neither
//! fails: nothing here passes without the model.
//!
//! The model is the vendor's behavioural reference. It enforces access privileges, latches them at a
//! reboot and keeps R-memory as the chip does, one command at a time. It does not model timing, tear
//! a write, or stand for a production chip's factory configuration.

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
use anchor_chip::Board;
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
const TAG_RESET_TARGET: u8 = 0x10;
/// The L2 byte that asks the chip for its response.
const L2_GET_RESPONSE: u8 = 0xAA;

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
    budget: Cell<Option<u64>>,
}

impl Power {
    pub fn cut_after(&self, transactions: u64) {
        self.budget.set(Some(transactions));
    }

    pub fn steady(&self) {
        self.budget.set(None);
    }

    /// Whether the budget has run out.
    pub fn was_cut(&self) -> bool {
        matches!(self.budget.get(), Some(0))
    }

    fn spend(&self) -> Result<(), SpiCut> {
        match self.budget.get() {
            Some(0) => return Err(SpiCut),
            Some(left) => self.budget.set(Some(left - 1)),
            None => {}
        }
        Ok(())
    }
}

fn call(stream: &mut TcpStream, tag: u8, payload: &[u8]) -> Vec<u8> {
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
        buffer.fill(0);
        buffer[..miso.len()].copy_from_slice(&miso);
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
    fn random_byte(&self) -> u8 {
        let mut byte = [0u8; 1];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut byte)) {
            Ok(()) => byte[0],
            Err(e) => panic!("no entropy: {e}"),
        }
    }
    fn wait_100ms(&self) {}
    fn alive(&self) {}
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
        let server = required_env("DSM_TROPIC01_MODEL_SERVER");
        let configuration = required_env("DSM_TROPIC01_MODEL_CFG");
        let port = match TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()) {
            Ok(address) => address.port(),
            Err(e) => panic!("no free port: {e}"),
        };
        let workdir = std::env::temp_dir().join(format!("dsm-tropic01-model-{port}"));
        if let Err(e) = std::fs::create_dir_all(&workdir) {
            panic!("no working directory for the model: {e}");
        }
        let child = Command::new(&server)
            .arg("tcp")
            .args(["-p", &port.to_string()])
            .arg("-c")
            .arg(&configuration)
            .arg("-o")
            .arg(workdir.join("model_out.yml"))
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
            power: Rc::new(Power::default()),
        }
    }

    fn connect(&self) -> TcpStream {
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

    /// A new chip from the factory.
    pub fn factory_reset(&self) {
        let mut stream = self.connect();
        call(&mut stream, TAG_RESET_TARGET, &[]);
    }

    /// Boot the anchor: what the monitor does at reset, on the same code.
    pub fn boot(&self) -> Result<BoardAnchor, BringUpError> {
        bring_up(self.power_cycle(), &SEALED, HostBoard)
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
