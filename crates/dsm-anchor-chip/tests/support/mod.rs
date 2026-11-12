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
use anchor_chip::Board;
use anchor_core::appliance::owner_authorization_digest;
use anchor_core::enrollment::{Install, Provisioning};
use anchor_core::proto::{decode_response, encode_request, pb};
use anchor_core::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use anchor_core::tropic::PartitionSig;
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
        HOST_STEPPING
    }
}

/// The stepping the host board reports, as the try-run's note shows it.
const HOST_STEPPING: u8 = 4;

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
        bring_up(self.power_cycle(), &SEALED, HostBoard, Install::ForGood)
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

    /// One frame, as the monitor hands it over: the anchor's own copy, held no longer than its
    /// request needs it.
    pub fn frame(&mut self, frame: Vec<u8>, measurement: Measurement) -> pb::ApplianceResponse {
        let anchor = match self.0.take() {
            Some(anchor) => anchor,
            None => panic!("the anchor is held here between requests"),
        };
        let (anchor, answer) = serve_measured(anchor, frame, measurement);
        self.0 = Some(anchor);
        match decode_response(&answer) {
            Ok(response) => response,
            Err(e) => panic!("the anchor answered no response: {e:?}"),
        }
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
        let (anchor, answer) = serve_measured(anchor, encode_request(request), measurement);
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

/// The owner's device key, BLAKE3-SPHINCS+ SPX256f from a fixed seed: the key [`provisioning`]
/// names, whose signature authorizes a prepare.
pub fn owner_key() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    KEY.get_or_init(
        || match anchor_chip::bring_up::SphincsPart::owner_keygen(&[0x0A; 32]) {
            Ok(key) => key,
            Err(e) => panic!("the owner's key: {e:?}"),
        },
    )
}

/// The owner-authorization digest of `prepare` on the anchor whose bundle is `bundle`, over the
/// `nonce` the anchor drew for it, and the owner's signature of it.
pub fn authorization_for(
    prepare: &pb::ApplianceRequest,
    bundle: &[u8],
    nonce: &[u8; 32],
) -> ([u8; 32], Vec<u8>) {
    let bundle: [u8; 32] = match bundle.try_into() {
        Ok(bundle) => bundle,
        Err(e) => panic!("a 32-byte bundle: {e}"),
    };
    let field = |bytes: &[u8], what: &str| -> [u8; 32] {
        match bytes.try_into() {
            Ok(array) => array,
            Err(e) => panic!("a 32-byte {what}: {e}"),
        }
    };
    let transition: OwnedTransition =
        match prepare.transition.as_ref().map(|t| t.to_owned_transition()) {
            Some(Ok(t)) => t,
            other => panic!(
                "a prepare's transition: {:?}",
                other.map(|r| r.map(|t| t.anchor_counter))
            ),
        };
    let challenge = field(&prepare.receiver_challenge, "challenge");
    let digest = owner_authorization_digest(
        &bundle,
        &transition.prev_root,
        transition.anchor_counter,
        &transition_digest(&transition.as_transition(), &challenge),
        &field(&prepare.sender_device_root_before, "device root"),
        &field(&prepare.sender_device_root_after, "device root"),
        nonce,
    );
    let signature = match anchor_chip::bring_up::SphincsPart::owner_sign(&owner_key().0, &digest) {
        Ok(sig) => sig,
        Err(e) => panic!("the owner signs: {e:?}"),
    };
    (digest, signature)
}

/// The wallet's rehearsal owner key, derived apart from its device key: what a try-run's payment is
/// authorized under.
pub fn rehearsal_key() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    KEY.get_or_init(
        || match anchor_chip::bring_up::SphincsPart::owner_keygen(&[0x0B; 32]) {
            Ok(key) => key,
            Err(e) => panic!("the rehearsal key: {e:?}"),
        },
    )
}

/// An `OP_AUTHORIZE` frame as it goes over the wire: the message, then the signature after it.
pub fn authorize_frame(digest: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut frame = encode_request(&pb::ApplianceRequest {
        op: pb::Op::Authorize as i32,
        authorization_digest: digest.to_vec(),
        ..Default::default()
    });
    frame.extend_from_slice(signature);
    frame
}

/// What the owner's device provisions the anchor with.
pub fn provisioning() -> Provisioning {
    Provisioning {
        device_id: [0x77; 32],
        online_id_pk: owner_key().1.clone(),
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
        rehearsal_pk: rehearsal_key().1.clone(),
        ..Default::default()
    }
}

// --- The receiver's side of an offline payment, on one chip ---------------------------------------
//
// The model is one chip, so its anchor pays itself and then receives that payment: every operation
// of a receive runs on the chip, its own release standing in for a payer's.

/// What the anchor discloses of its enrollment, from its STATUS and the provisioning.
pub fn disclosure_of(status: &pb::ApplianceResponse) -> pb::PayerDisclosure {
    let provisioning = provisioning();
    pb::PayerDisclosure {
        online_id_pk: provisioning.online_id_pk,
        anchor_id: status.pin_anchor_id.clone(),
        chip_pk: status.pin_chip_pk.clone(),
        partition_pk: status.pin_partition_pk.clone(),
        enrolled_counter: match u32::try_from(status.pin_enrolled_counter) {
            Ok(h0) => h0,
            Err(e) => panic!("the enrolled counter fits: {e}"),
        },
        device_id: provisioning.device_id.to_vec(),
        policy_hash: provisioning.policy_hash.to_vec(),
        birth_commitment: status.pin_birth_commitment.clone(),
    }
}

/// A payment from the provisioned device to itself, from the frontier `prev` at counter `u`.
pub fn self_payment(prev: [u8; 32], u: u64, challenge: &[u8; 32]) -> OwnedTransition {
    let device = provisioning().device_id;
    let mut t = OwnedTransition {
        relationship_id: [1; 32],
        object_id: [2; 32],
        sender_device_id: device,
        recipient_device_id: device,
        prev_root: prev,
        next_root: prev,
        anchor_counter: u,
        next_anchor_counter: u + 1,
        action_type: anchor_core::receive::ACTION_TRANSFER,
        action_fields: Vec::new(),
        payload_hash: [6; 32],
        old_leaf_proof: Vec::new(),
        new_leaf_proof: Vec::new(),
        authority_policy_hash: provisioning().policy_hash,
    };
    t.next_root = anchor_root_advance(&prev, &transition_digest(&t.as_transition(), challenge));
    t
}

/// The receive of `paid` from the frontier `prev` at counter `u`, under `challenge`.
pub fn receive_of(
    paid: &anchor_core::root_advance::OfflineRelease,
    prev: [u8; 32],
    u: u64,
    challenge: &[u8; 32],
) -> OwnedTransition {
    let mut t = OwnedTransition {
        sender_device_id: provisioning().device_id,
        recipient_device_id: paid.transition.sender_device_id,
        prev_root: prev,
        next_root: prev,
        anchor_counter: u,
        next_anchor_counter: u + 1,
        action_type: anchor_core::receive::ACTION_RECEIVE,
        action_fields: anchor_core::receive::receive_action_fields(
            &paid.cert.anchor_bundle,
            &paid.cert.root_advance_message,
            paid.cert.next_anchor_counter,
        ),
        old_leaf_proof: Vec::new(),
        new_leaf_proof: Vec::new(),
        ..paid.transition.clone()
    };
    t.next_root = anchor_root_advance(&prev, &transition_digest(&t.as_transition(), challenge));
    t
}

pub fn prepare_of(
    t: &OwnedTransition,
    challenge: &[u8; 32],
    before: [u8; 32],
    after: [u8; 32],
) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: pb::Op::Prepare as i32,
        transition: Some(t.to_pb()),
        receiver_challenge: challenge.to_vec(),
        sender_device_root_before: before.to_vec(),
        sender_device_root_after: after.to_vec(),
        ..Default::default()
    }
}

/// A payment check of `paid`, as the wallet sends it: the transition and the certificate only.
pub fn check_of(
    paid: &anchor_core::root_advance::OfflineRelease,
    payer: &pb::PayerDisclosure,
) -> pb::ApplianceRequest {
    pb::ApplianceRequest {
        op: pb::Op::CheckPayment as i32,
        payment: Some(Box::new(pb::OfflineRelease {
            transition: Some(paid.transition.to_pb()),
            cert: Some(paid.cert.to_pb()),
            ..Default::default()
        })),
        payer: Some(Box::new(payer.clone())),
        ..Default::default()
    }
}

/// The value of a step that must succeed, or the test fails naming it.
pub fn served(answer: pb::ApplianceResponse, what: &str) -> pb::ApplianceResponse {
    assert!(
        answer.ok,
        "{what}: error {} {}",
        answer.error, answer.detail
    );
    answer
}

pub fn thirty_two(bytes: &[u8], what: &str) -> [u8; 32] {
    match bytes.try_into() {
        Ok(array) => array,
        Err(e) => panic!("{what} is 32 bytes: {e}"),
    }
}
