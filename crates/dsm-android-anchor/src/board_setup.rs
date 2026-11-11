// SPDX-License-Identifier: MIT OR Apache-2.0
//! The phone's board setup ([`dsm_sdk::bridge::AnchorBoardSetup`]): a board's one-time burns from
//! the phone alone, through the board's own USB bootloader while it is in BOOTSEL (owner,
//! 2026-11-11: "Not everyone has a Mac. It has to be doable from the phone").
//!
//! Every call reads the board fresh and says where it stands ([`crate::otp_burn::Standing`]). A step
//! runs only when it is the board's next, and only on the board whose chip id the person typed back:
//! a board swapped between the read and the step is refused. Every write is read back before the
//! step is said to be done.

use dsm::types::proto as pb;

use crate::otp_burn::{self, Burn, Next, OnBoard, OtpReading, SecretPage, Standing};
use crate::picoboot::{BootselLink, Picoboot};
use crate::release::Release;

use pb::AnchorBoardStepKind as Kind;
use pb::AnchorBoardStepState as State;

/// What the setup needs of the phone: the board's USB link, the release the app carries, and the
/// phone's own random source.
pub trait BoardPort: Send + Sync {
    type Link: BootselLink;
    /// The board in BOOTSEL: its link, and its chip id as its bootloader names itself (its USB serial
    /// number, 16 hexadecimal digits).
    fn open(&self) -> Result<(Self::Link, String), String>;
    /// The production release this app carries.
    fn release(&self) -> Result<Release, String>;
    /// 32 bytes from the phone's random source, for a blank board's secret.
    fn secret(&self) -> Result<[u8; 32], String>;
    /// After a reboot: wait for the board to leave USB and come back, and say how it came back.
    fn wait_for_return(&self, chip_id: &str) -> Result<Returned, String>;
}

/// How a board came back after a reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Returned {
    /// In BOOTSEL, with the same chip id: it found no image it may run.
    Bootsel,
    /// As the DSM Anchor: it ran the image in its flash.
    AsAnchor,
}

/// The steps in the runbook's order.
const ORDER: [Kind; 8] = [
    Kind::LoadImage,
    Kind::SealSecret,
    Kind::WriteDigest,
    Kind::LockDigest,
    Kind::WriteBootKey,
    Kind::Lockdown,
    Kind::Boot,
    Kind::LockBootPages,
];

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::LoadImage => "Load the signed image into flash",
        Kind::SealSecret => "Write the board's secret and lock its page",
        Kind::WriteDigest => "Burn the firmware digest",
        Kind::LockDigest => "Lock the digest page",
        Kind::WriteBootKey => "Burn the boot key's hash",
        Kind::Lockdown => "Lock down: secure boot on, debug off",
        Kind::Boot => "Start the signed image once",
        Kind::LockBootPages => "Lock the boot pages",
        Kind::CheckChangedImage => "Check that a changed image is refused",
        Kind::Unspecified => "no step",
    }
}

/// Loading flash can be done again; every other step writes OTP, the first boot included (it records
/// the image's rollback version).
fn permanent(kind: Kind) -> bool {
    kind != Kind::LoadImage
}

fn burn_kind(burn: Burn) -> Kind {
    match burn {
        Burn::SealSecret => Kind::SealSecret,
        Burn::WriteDigest => Kind::WriteDigest,
        Burn::LockDigestPage => Kind::LockDigest,
        Burn::WriteBootKey => Kind::WriteBootKey,
        Burn::Lockdown => Kind::Lockdown,
        Burn::LockBootPages => Kind::LockBootPages,
    }
}

/// The chip id as the bootloader gives it: upper case, no `0x`.
fn normalized(chip_id: &str) -> String {
    let upper = chip_id.trim().to_ascii_uppercase();
    match upper.strip_prefix("0X") {
        Some(digits) => digits.to_string(),
        None => upper,
    }
}

/// A chip id as an RP2350's bootloader names itself: 16 hexadecimal digits.
fn is_chip_id(chip_id: &str) -> bool {
    chip_id.len() == 16 && chip_id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A board read: where it stands, and the step it needs next (none once every step is done).
struct Read {
    standing: Standing,
    next: Option<Kind>,
    found: Vec<String>,
}

fn read_board<L: BootselLink>(boot: &mut Picoboot<L>, release: &Release) -> Result<Read, String> {
    let otp = OtpReading::read(boot).map_err(|e| e.to_string())?;
    let standing = Standing::read(boot, &otp)?;
    let mut found = Vec::new();
    if standing.secret == SecretPage::Sealed && standing.digest == otp_burn::Hash32::Blank {
        found.push(
            "the board's secret is sealed by an earlier procedure: it keeps that secret"
                .to_string(),
        );
    }
    let next = match otp_burn::next(&standing, release)? {
        Next::Done => None,
        // The first boot runs what flash holds: the signed image, or it is loaded again first (after
        // the changed-image check, flash may hold the changed one).
        Next::Boot => match otp_burn::image_on_board(boot, release)? {
            OnBoard::Release => Some(Kind::Boot),
            OnBoard::Differs { .. } => Some(Kind::LoadImage),
        },
        Next::Burn(burn) => {
            // Step 3 comes before the first burn on a board: the image goes into flash first.
            let first = matches!(burn, Burn::SealSecret | Burn::WriteDigest);
            if first {
                found.extend(otp_burn::check_blank(&otp)?.locks_already_set);
                match otp_burn::image_on_board(boot, release)? {
                    OnBoard::Release => Some(burn_kind(burn)),
                    OnBoard::Differs { .. } => Some(Kind::LoadImage),
                }
            } else {
                Some(burn_kind(burn))
            }
        }
    };
    Ok(Read {
        standing,
        next,
        found,
    })
}

/// Each step's state: done before the next, the next, later after it. A secret sealed by an earlier
/// procedure is done whatever comes next.
fn steps(read: &Read) -> Vec<pb::AnchorBoardStep> {
    let next_at = read
        .next
        .and_then(|next| ORDER.iter().position(|k| *k == next));
    ORDER
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            let state = match next_at {
                _ if *kind == Kind::SealSecret && read.standing.secret == SecretPage::Sealed => {
                    State::Done
                }
                None => State::Done,
                Some(at) if i < at => State::Done,
                Some(at) if i == at => State::Next,
                Some(_later) => State::Later,
            };
            pb::AnchorBoardStep {
                kind: *kind as i32,
                state: state as i32,
                permanent: permanent(*kind),
                name: kind_name(*kind).to_string(),
            }
        })
        .collect()
}

fn release_words(release: &Release) -> String {
    format!(
        "the production release this app carries: a signed image of {} bytes",
        release.image.len()
    )
}

/// The board setup over a phone's port.
pub struct BoardSetup<P: BoardPort> {
    port: P,
}

impl<P: BoardPort> BoardSetup<P> {
    pub fn new(port: P) -> Self {
        Self { port }
    }

    fn answer(
        &self,
        boot: &mut Picoboot<P::Link>,
        chip_id: &str,
        release: &Release,
    ) -> pb::AnchorBoardResponse {
        let base = pb::AnchorBoardResponse {
            board_connected: is_chip_id(chip_id),
            chip_id: chip_id.to_string(),
            release: release_words(release),
            ..Default::default()
        };
        match read_board(boot, release) {
            Ok(read) => pb::AnchorBoardResponse {
                steps: steps(&read),
                done: read.next.is_none(),
                found: read.found,
                ..base
            },
            Err(why) => pb::AnchorBoardResponse {
                refused: why,
                ..base
            },
        }
    }

    /// Step 9's check: the release's image with one code byte changed, loaded and booted. The board
    /// must come back in BOOTSEL; then the signed image is loaded back and read back whole. A board
    /// that comes back as the anchor ran an image not as signed: its secure boot is not in force.
    fn check_changed_image(
        &self,
        mut boot: Picoboot<P::Link>,
        chip_id: &str,
        release: &Release,
    ) -> pb::AnchorBoardResponse {
        let gone = pb::AnchorBoardResponse {
            chip_id: chip_id.to_string(),
            release: release_words(release),
            ..Default::default()
        };
        if let Err(why) = otp_burn::boot_changed_image(&mut boot, release) {
            let mut answer = self.answer(&mut boot, chip_id, release);
            answer.refused = why;
            return answer;
        }
        // The board is rebooting: its link goes with it.
        drop(boot);
        match self.port.wait_for_return(chip_id) {
            Err(why) => pb::AnchorBoardResponse {
                refused: format!("the board did not come back after the changed image: {why}"),
                ..gone
            },
            Ok(Returned::AsAnchor) => pb::AnchorBoardResponse {
                refused: "the board RAN an image not as signed: its secure boot is not in force. \
                          Stop: do not start it, lock its boot pages or install it"
                    .to_string(),
                ..gone
            },
            Ok(Returned::Bootsel) => {
                let reopened = self.port.open().and_then(|(link, id)| {
                    if id == chip_id {
                        Picoboot::connect(link).map_err(|e| e.to_string())
                    } else {
                        Err(format!("another board came back: {id}"))
                    }
                });
                let mut boot = match reopened {
                    Ok(boot) => boot,
                    Err(why) => {
                        return pb::AnchorBoardResponse {
                            refused: format!(
                                "the changed image was refused and the board came back in BOOTSEL, \
                                 but it could not be opened again: {why}. Read it again, and load \
                                 the signed image back"
                            ),
                            ..gone
                        }
                    }
                };
                match otp_burn::load_image(&mut boot, release) {
                    Ok(()) => {
                        let mut answer = self.answer(&mut boot, chip_id, release);
                        answer.written = vec![
                            "a changed image was refused: the board found no image it may run and \
                             came back in BOOTSEL"
                                .to_string(),
                            format!(
                                "flash: the signed image again, {} bytes, read back whole",
                                release.image.len()
                            ),
                        ];
                        answer
                    }
                    Err(why) => {
                        let mut answer = self.answer(&mut boot, chip_id, release);
                        answer.refused = format!(
                            "the changed image was refused, and loading the signed image back \
                             failed: {why}"
                        );
                        answer
                    }
                }
            }
        }
    }

    fn run(
        &self,
        boot: &mut Picoboot<P::Link>,
        release: &Release,
        step: Kind,
    ) -> Result<Vec<String>, String> {
        let burn = |b: Burn, boot: &mut Picoboot<P::Link>| -> Result<Vec<String>, String> {
            otp_burn::burn(boot, release, b, || self.port.secret()).map(|done| done.rows)
        };
        match step {
            Kind::LoadImage => otp_burn::load_image(boot, release).map(|()| {
                vec![format!(
                    "flash: the signed image, {} bytes, read back whole",
                    release.image.len()
                )]
            }),
            Kind::SealSecret => burn(Burn::SealSecret, boot),
            Kind::WriteDigest => burn(Burn::WriteDigest, boot),
            Kind::LockDigest => burn(Burn::LockDigestPage, boot),
            Kind::WriteBootKey => burn(Burn::WriteBootKey, boot),
            Kind::Lockdown => burn(Burn::Lockdown, boot),
            Kind::Boot => otp_burn::boot(boot, release).map(|()| {
                vec![
                    "the board is starting its signed image, and its first boot records the image's \
                     rollback version. Once it has started, unplug it, hold BOOTSEL, and plug it in \
                     again for the last step"
                        .to_string(),
                ]
            }),
            Kind::LockBootPages => burn(Burn::LockBootPages, boot),
            // It reboots the board and waits for it to come back: `check_changed_image` runs it.
            Kind::CheckChangedImage => Err(
                "the changed-image check runs on its own, across the board's reboot".to_string(),
            ),
            Kind::Unspecified => Err("no step was named".to_string()),
        }
    }
}

impl<P: BoardPort> dsm_sdk::bridge::AnchorBoardSetup for BoardSetup<P> {
    fn read(&self) -> pb::AnchorBoardResponse {
        let release = match self.port.release() {
            Ok(r) => r,
            Err(why) => {
                return pb::AnchorBoardResponse {
                    release: format!("this app carries no production release: {why}"),
                    refused: "a board is set up only toward the release the app carries"
                        .to_string(),
                    ..Default::default()
                }
            }
        };
        let (link, chip_id) = match self.port.open() {
            Ok(opened) => opened,
            Err(why) => {
                return pb::AnchorBoardResponse {
                    release: release_words(&release),
                    refused: why,
                    ..Default::default()
                }
            }
        };
        match Picoboot::connect(link) {
            Ok(mut boot) => self.answer(&mut boot, &chip_id, &release),
            Err(why) => pb::AnchorBoardResponse {
                chip_id,
                release: release_words(&release),
                refused: why.to_string(),
                ..Default::default()
            },
        }
    }

    fn step(&self, request: &pb::AnchorBoardStepRequest) -> pb::AnchorBoardResponse {
        let release = match self.port.release() {
            Ok(r) => r,
            Err(why) => {
                return pb::AnchorBoardResponse {
                    release: format!("this app carries no production release: {why}"),
                    refused: "a board is set up only toward the release the app carries"
                        .to_string(),
                    ..Default::default()
                }
            }
        };
        let (link, chip_id) = match self.port.open() {
            Ok(opened) => opened,
            Err(why) => {
                return pb::AnchorBoardResponse {
                    release: release_words(&release),
                    refused: why,
                    ..Default::default()
                }
            }
        };
        let mut boot = match Picoboot::connect(link) {
            Ok(boot) => boot,
            Err(why) => {
                return pb::AnchorBoardResponse {
                    chip_id,
                    release: release_words(&release),
                    refused: why.to_string(),
                    ..Default::default()
                }
            }
        };
        if normalized(&request.chip_id) != chip_id {
            let mut answer = self.answer(&mut boot, &chip_id, &release);
            answer.refused = format!(
                "the chip id given, {}, is not this board's: the board on USB is {chip_id}. Nothing \
                 was written",
                normalized(&request.chip_id)
            );
            return answer;
        }
        let Ok(step) = Kind::try_from(request.step) else {
            let mut answer = self.answer(&mut boot, &chip_id, &release);
            answer.refused = format!("step {} is not one this app knows", request.step);
            return answer;
        };
        let due = match read_board(&mut boot, &release) {
            Ok(read) => read.next,
            Err(why) => {
                let mut answer = self.answer(&mut boot, &chip_id, &release);
                answer.refused = why;
                return answer;
            }
        };
        if step == Kind::CheckChangedImage {
            if due != Some(Kind::Boot) {
                let mut answer = self.answer(&mut boot, &chip_id, &release);
                answer.refused = "the changed-image check comes after the lockdown and before the \
                                  first boot; nothing was written"
                    .to_string();
                return answer;
            }
            return self.check_changed_image(boot, &chip_id, &release);
        }
        if due != Some(step) {
            let mut answer = self.answer(&mut boot, &chip_id, &release);
            answer.refused = format!(
                "{} is not this board's next step; nothing was written",
                kind_name(step)
            );
            return answer;
        }
        match self.run(&mut boot, &release, step) {
            // The board has rebooted into its image and left BOOTSEL: there is nothing to read.
            Ok(written) if step == Kind::Boot => pb::AnchorBoardResponse {
                chip_id,
                release: release_words(&release),
                written,
                ..Default::default()
            },
            Ok(written) => {
                let mut answer = self.answer(&mut boot, &chip_id, &release);
                answer.written = written;
                answer
            }
            Err(why) => {
                let mut answer = self.answer(&mut boot, &chip_id, &release);
                answer.refused = why;
                answer
            }
        }
    }
}

/// The Android port: the board's link and the release through up-calls to Kotlin (`Unified`), which
/// only moves bytes, and the phone's random source.
#[cfg(target_os = "android")]
pub mod jni_port {
    use super::BoardPort;
    use crate::picoboot::BootselLink;
    use crate::release::Release;
    use jni::objects::{JByteArray, JClass, JObject, JString, JValue, JValueOwned};
    use jni::JNIEnv;

    const UNIFIED: &str = "com/dsm/wallet/bridge/Unified";

    /// Run `f` with a mutable env and Kotlin's `Unified`, as `usb_pico`'s up-call does.
    fn with_unified<T>(
        f: impl for<'b> FnOnce(&mut JNIEnv<'b>, &JClass<'b>) -> Result<T, String>,
    ) -> Result<T, String> {
        dsm_sdk::jni::jni_common::with_env(|env| {
            let mut env = unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _) }
                .map_err(|e| format!("clone JNIEnv: {e}"))?;
            let cls = dsm_sdk::jni::jni_common::find_class_with_app_loader(&mut env, UNIFIED)?;
            f(&mut env, &cls)
        })
    }

    /// A `byte[]` Kotlin returned, or none for its null.
    fn bytes(
        env: &mut JNIEnv<'_>,
        value: JValueOwned<'_>,
        name: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let obj = value
            .l()
            .map_err(|e| format!("{name}: not an object: {e}"))?;
        if obj.is_null() {
            return Ok(None);
        }
        env.convert_byte_array(JByteArray::from(obj))
            .map(Some)
            .map_err(|e| format!("{name}: {e}"))
    }

    fn call_bytes(
        name: &'static str,
        sig: &'static str,
        arg: Option<i32>,
    ) -> Result<Option<Vec<u8>>, String> {
        with_unified(|env, cls| {
            let args: Vec<JValue> = arg.map(JValue::Int).into_iter().collect();
            let res = env
                .call_static_method(cls, name, sig, &args)
                .map_err(|e| format!("call {name}: {e}"))?;
            bytes(env, res, name)
        })
    }

    fn call_int(name: &'static str) -> Result<i32, String> {
        with_unified(|env, cls| {
            env.call_static_method(cls, name, "()I", &[])
                .and_then(|v| v.i())
                .map_err(|e| format!("call {name}: {e}"))
        })
    }

    fn call_string(name: &'static str) -> Result<Option<String>, String> {
        with_unified(|env, cls| {
            let res = env
                .call_static_method(cls, name, "()Ljava/lang/String;", &[])
                .map_err(|e| format!("call {name}: {e}"))?;
            let obj = res.l().map_err(|e| format!("{name}: not an object: {e}"))?;
            if obj.is_null() {
                return Ok(None);
            }
            let s: String = env
                .get_string(&JString::from(obj))
                .map_err(|e| format!("{name}: {e}"))?
                .into();
            Ok(Some(s))
        })
    }

    /// Why Kotlin's last BOOTSEL call failed.
    fn last_error() -> String {
        match call_string("bootselLastError") {
            Ok(Some(why)) => why,
            Ok(None) => "the USB link gave no reason".to_string(),
            Err(e) => e,
        }
    }

    pub struct JniBoardPort;

    /// The link to a board in BOOTSEL, open while this lives.
    pub struct JniBootselLink;

    impl Drop for JniBootselLink {
        fn drop(&mut self) {
            if let Err(e) = call_int("bootselClose") {
                log::warn!("[board-setup] closing the BOOTSEL link: {e}");
            }
        }
    }

    impl BootselLink for JniBootselLink {
        fn bulk_out(&mut self, data: &[u8]) -> Result<(), String> {
            let sent = with_unified(|env, cls| {
                let arr = env
                    .byte_array_from_slice(data)
                    .map_err(|e| format!("byte_array_from_slice: {e}"))?;
                let arr_obj = JObject::from(arr);
                env.call_static_method(cls, "bootselBulkOut", "([B)I", &[JValue::Object(&arr_obj)])
                    .and_then(|v| v.i())
                    .map_err(|e| format!("call bootselBulkOut: {e}"))
            })?;
            match usize::try_from(sent) {
                Ok(n) if n == data.len() => Ok(()),
                _short => Err(format!(
                    "sent {sent} of {} bytes: {}",
                    data.len(),
                    last_error()
                )),
            }
        }

        fn bulk_in(&mut self, max: usize) -> Result<Vec<u8>, String> {
            let len = i32::try_from(max).map_err(|e| e.to_string())?;
            call_bytes("bootselBulkIn", "(I)[B", Some(len))?.ok_or_else(last_error)
        }

        fn ack_in(&mut self) -> Result<(), String> {
            match call_int("bootselAckIn")? {
                0 => Ok(()),
                _failed => Err(last_error()),
            }
        }

        fn command_status(&mut self) -> Result<[u8; 16], String> {
            let status =
                call_bytes("bootselCommandStatus", "()[B", None)?.ok_or_else(last_error)?;
            status
                .as_slice()
                .try_into()
                .map_err(|_short| format!("a status of {} bytes, not 16", status.len()))
        }

        /// picotool's `picoboot_reset`: each endpoint that reports a halt cleared as libusb clears it,
        /// then the interface reset.
        fn reset(&mut self) -> Result<(), String> {
            let halted = with_unified(|env, cls| {
                let res = env
                    .call_static_method(cls, "bootselHaltedEndpoints", "()[I", &[])
                    .map_err(|e| format!("call bootselHaltedEndpoints: {e}"))?;
                let obj = res
                    .l()
                    .map_err(|e| format!("bootselHaltedEndpoints: {e}"))?;
                if obj.is_null() {
                    return Ok(None);
                }
                let array = jni::objects::JIntArray::from(obj);
                let len = env.get_array_length(&array).map_err(|e| e.to_string())?;
                let mut addresses = vec![0i32; usize::try_from(len).map_err(|e| e.to_string())?];
                env.get_int_array_region(&array, 0, &mut addresses)
                    .map_err(|e| e.to_string())?;
                Ok(Some(addresses))
            })?
            .ok_or_else(last_error)?;
            if !halted.is_empty() {
                let fd = call_int("bootselFileDescriptor")?;
                for endpoint in halted {
                    clear_halt(fd, endpoint)?;
                }
            }
            match call_int("bootselInterfaceReset")? {
                0 => Ok(()),
                _failed => Err(last_error()),
            }
        }
    }

    /// `USBDEVFS_CLEAR_HALT` (`_IOR('U', 21, unsigned int)`): the device's halt cleared and the host's
    /// endpoint state with it, its data toggle included, as libusb's Linux backend clears a halt.
    const USBDEVFS_CLEAR_HALT: u32 = 0x8004_5515;

    fn clear_halt(fd: i32, endpoint: i32) -> Result<(), String> {
        let mut address = libc::c_uint::try_from(endpoint).map_err(|e| e.to_string())?;
        // SAFETY: `fd` is the usbfs descriptor Android opened for this connection, live while the
        // link is; the ioctl reads one `unsigned int`, the endpoint address, from `address`.
        let rc = unsafe { libc::ioctl(fd, USBDEVFS_CLEAR_HALT as _, &mut address) };
        if rc < 0 {
            return Err(format!(
                "clearing the halt of endpoint {endpoint:#04x}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// One file of the release the app carries, from its assets.
    fn release_file(name: &str) -> Result<Vec<u8>, String> {
        let path = format!("anchor-release/{name}");
        let found = with_unified(|env, cls| {
            let jpath = env.new_string(&path).map_err(|e| e.to_string())?;
            let jobj = JObject::from(jpath);
            let res = env
                .call_static_method(
                    cls,
                    "anchorReleaseFile",
                    "(Ljava/lang/String;)[B",
                    &[JValue::Object(&jobj)],
                )
                .map_err(|e| format!("call anchorReleaseFile: {e}"))?;
            bytes(env, res, "anchorReleaseFile")
        })?;
        found.ok_or_else(|| format!("the app carries no {path}"))
    }

    impl BoardPort for JniBoardPort {
        type Link = JniBootselLink;

        fn open(&self) -> Result<(JniBootselLink, String), String> {
            match call_string("bootselOpen")? {
                Some(chip_id) => Ok((JniBootselLink, chip_id)),
                None => Err(last_error()),
            }
        }

        fn release(&self) -> Result<Release, String> {
            Release::from_signing(
                &release_file("signed.elf")?,
                &release_file("ns_app.bin")?,
                &release_file("mu-enrolled.bin")?,
                &release_file("bootkey0.bin")?,
            )
        }

        /// Filled from the phone's random source into memory never initialised to anything else.
        fn wait_for_return(&self, chip_id: &str) -> Result<super::Returned, String> {
            let returned = with_unified(|env, cls| {
                let jid = env.new_string(chip_id).map_err(|e| e.to_string())?;
                let jobj = JObject::from(jid);
                env.call_static_method(
                    cls,
                    "bootselWaitForReturn",
                    "(Ljava/lang/String;)I",
                    &[JValue::Object(&jobj)],
                )
                .and_then(|v| v.i())
                .map_err(|e| format!("call bootselWaitForReturn: {e}"))
            })?;
            match returned {
                0 => Ok(super::Returned::Bootsel),
                1 => Ok(super::Returned::AsAnchor),
                _neither => Err(last_error()),
            }
        }

        fn secret(&self) -> Result<[u8; 32], String> {
            let mut fresh = [core::mem::MaybeUninit::<u8>::uninit(); 32];
            let drawn = getrandom::fill_uninit(&mut fresh)
                .map_err(|e| format!("the phone's random source: {e}"))?;
            <[u8; 32]>::try_from(&*drawn)
                .map_err(|_short| format!("{} random bytes for 32", drawn.len()))
        }
    }
}
