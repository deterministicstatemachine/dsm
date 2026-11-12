// SPDX-License-Identifier: MIT OR Apache-2.0
//! The burn procedure against a model of the board's bootloader that keeps OTP's rules
//! ([`crate::bootrom_model`]): the boards in hand as they stood on 2026-11-11, burned from the phone.

use crate::bootrom_model::{BootromModel, LastBoot};
use crate::otp_burn::{
    burn, check_blank, load_image, lock0, lock1, next, Burn, Hash32, Next, OtpReading, SecretPage,
    Standing, BOOT_PAGES_LOCK, CRIT1_ROW, DIGEST_LOCK, DIGEST_ROW, ROLLBACK_LOCK, SECRET_LOCK,
    SECRET_ROW,
};
use crate::picoboot::{BootselError, Picoboot};
use crate::release::{flatten_elf, Release, FLASH_BASE};

/// A 32-bit little-endian ARM ELF loading each `(address, bytes)` as its own segment.
fn elf(segments: &[(u32, &[u8])]) -> Vec<u8> {
    let phoff = 52usize;
    let data_at = phoff + 32 * segments.len();
    let mut out = vec![0u8; data_at];
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 1;
    out[5] = 1;
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes());
    out[18..20].copy_from_slice(&40u16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[28..32].copy_from_slice(&(phoff as u32).to_le_bytes());
    out[40..42].copy_from_slice(&52u16.to_le_bytes());
    out[42..44].copy_from_slice(&32u16.to_le_bytes());
    out[44..46].copy_from_slice(&(segments.len() as u16).to_le_bytes());
    for (i, (addr, bytes)) in segments.iter().enumerate() {
        let ph = phoff + 32 * i;
        let offset = out.len() as u32;
        out[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        out[ph + 4..ph + 8].copy_from_slice(&offset.to_le_bytes());
        out[ph + 8..ph + 12].copy_from_slice(&addr.to_le_bytes());
        out[ph + 12..ph + 16].copy_from_slice(&addr.to_le_bytes());
        out[ph + 16..ph + 20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        out[ph + 20..ph + 24].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// A Non-secure app, and a signed image that holds it after a monitor of its own bytes.
fn signing() -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let ns_app: Vec<u8> = (0..2048u32).map(|i| (i * 7 + 3) as u8).collect();
    let monitor: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let signed = elf(&[(FLASH_BASE, &monitor), (FLASH_BASE + 0x2000, &ns_app)]);
    let digest = *blake3::hash(&ns_app).as_bytes();
    let boot_key: [u8; 32] = core::array::from_fn(|i| (0x70 + i) as u8);
    (signed, ns_app, digest, boot_key)
}

fn release() -> Release {
    let (signed, ns_app, digest, boot_key) = signing();
    Release::from_signing(&signed, &ns_app, &digest, &boot_key).expect("the release holds together")
}

fn standing(pb: &mut Picoboot<BootromModel>) -> Standing {
    let otp = OtpReading::read(pb).expect("read the OTP");
    Standing::read(pb, &otp).expect("where the board stands")
}

const SECRET: [u8; 32] = [0x5c; 32];

#[test]
fn the_lock_values_are_the_scripts() {
    // provision-otp.sh: the secret page's lock 0x3d3d3d, the boot pages' 0x151515 (RUNBOOK Step 0).
    assert_eq!(SECRET_LOCK, 0x3d_3d3d);
    assert_eq!(BOOT_PAGES_LOCK, 0x15_1515);
    assert_eq!(DIGEST_LOCK, 0x1d_1d1d);
    assert_eq!(ROLLBACK_LOCK, 0x14_1414);
}

#[test]
fn an_elf_flattens_to_flash_as_objcopy_lays_it_out() {
    let a = [1u8, 2, 3];
    let b = [9u8, 8];
    let image = flatten_elf(&elf(&[(FLASH_BASE, &a), (FLASH_BASE + 8, &b)])).expect("flatten");
    assert_eq!(image, vec![1, 2, 3, 0, 0, 0, 0, 0, 9, 8]);
    let ram = flatten_elf(&elf(&[(FLASH_BASE, &a), (0x2000_0000, &b)]))
        .expect_err("a segment in RAM cannot be loaded into flash");
    assert!(ram.contains("outside flash"), "{ram}");
    let late = flatten_elf(&elf(&[(FLASH_BASE + 0x100, &a)]))
        .expect_err("an image that does not start at the flash's first byte");
    assert!(late.contains("not at the flash's first byte"), "{late}");
}

#[test]
fn a_release_whose_digest_is_not_its_apps_is_refused() {
    let (signed, ns_app, mut digest, boot_key) = signing();
    digest[0] ^= 1;
    let refused = Release::from_signing(&signed, &ns_app, &digest, &boot_key)
        .expect_err("a digest not the Non-secure app's would brick the board's authority");
    assert!(refused.contains("not the Non-secure app's"), "{refused}");
    let (signed, mut ns_app, _, boot_key) = signing();
    ns_app[0] ^= 1;
    let other = *blake3::hash(&ns_app).as_bytes();
    let refused = Release::from_signing(&signed, &ns_app, &other, &boot_key)
        .expect_err("an app the signed image does not hold");
    assert!(
        refused.contains("does not hold the Non-secure app"),
        "{refused}"
    );
}

#[test]
fn the_boards_in_hand_check_blank_with_their_secret_sealed() {
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    let otp = OtpReading::read(&mut pb).expect("read");
    assert!(
        otp.unreadable_pages.contains(&48),
        "the sealed page is the bootloader's to read: none"
    );
    let blank = check_blank(&otp).expect("blank where the procedure writes");
    assert_eq!(blank.secret, SecretPage::Sealed);
    assert_eq!(
        blank.locks_already_set.len(),
        2,
        "{:?}",
        blank.locks_already_set
    );
    assert!(blank.locks_already_set[0].contains("0x40404"));
}

#[test]
fn a_sealed_board_is_burned_from_the_phone_in_the_runbooks_order() {
    let release = release();
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    assert_eq!(
        next(&standing(&mut pb), &release),
        Ok(Next::Burn(Burn::WriteDigest))
    );

    // The digest waits for the image: Step 3 comes first.
    let early = burn(&mut pb, &release, Burn::WriteDigest, || Ok(SECRET))
        .expect_err("the digest burned before its image is in flash");
    assert!(early.contains("load the image first"), "{early}");
    assert_eq!(
        standing(&mut pb).digest,
        Hash32::Blank,
        "nothing was written"
    );
    load_image(&mut pb, &release).expect("Step 3");

    for step in [
        Burn::WriteDigest,
        Burn::LockDigestPage,
        Burn::WriteBootKey,
        Burn::Lockdown,
    ] {
        let done =
            burn(&mut pb, &release, step, || Ok(SECRET)).expect("the step burns and reads back");
        assert!(!done.rows.is_empty());
    }
    let after = standing(&mut pb);
    assert_eq!(after.digest, Hash32::Holds(release.digest));
    assert_eq!(after.boot_key, Hash32::Holds(release.boot_key_hash));
    assert!(after.digest_page_locked && after.locked_down);
    assert_eq!(next(&after, &release), Ok(Next::Boot));

    // Step 9b waits for the signed image's first boot, which records its rollback version.
    let early = burn(&mut pb, &release, Burn::LockBootPages, || Ok(SECRET))
        .expect_err("the boot pages locked before the first boot");
    assert!(early.contains("it needs Boot"), "{early}");
    crate::otp_burn::boot(&mut pb, &release).expect("Step 9");
    assert_eq!(pb_model(&mut pb).rebooted, 1);
    assert_eq!(
        next(&standing(&mut pb), &release),
        Ok(Next::Burn(Burn::LockBootPages))
    );
    burn(&mut pb, &release, Burn::LockBootPages, || Ok(SECRET)).expect("Step 9b");
    assert_eq!(next(&standing(&mut pb), &release), Ok(Next::Done));

    let model = pb_model(&mut pb);
    assert_eq!(
        model.raw[usize::from(lock1(1))],
        BOOT_PAGES_LOCK,
        "0x040404 grown to 0x151515"
    );
    assert_eq!(
        model.raw[usize::from(CRIT1_ROW)] & 0b101,
        0b101,
        "secure boot on, debug off"
    );
    assert_eq!(
        model.raw[0x4b] & 0x0f0f,
        0x0e01,
        "key 0 valid, keys 1-3 invalid"
    );
    for copy in 0..8 {
        assert_eq!(
            model.raw[usize::from(CRIT1_ROW) + copy],
            model.raw[usize::from(CRIT1_ROW)]
        );
    }
}

/// The model behind a connection, to look at what the board now holds.
fn pb_model(pb: &mut Picoboot<BootromModel>) -> &mut BootromModel {
    pb.link_mut()
}

#[test]
fn a_step_out_of_order_writes_nothing() {
    let release = release();
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    load_image(&mut pb, &release).expect("Step 3");
    let before = pb_model(&mut pb).raw.clone();
    for step in [
        Burn::Lockdown,
        Burn::WriteBootKey,
        Burn::LockDigestPage,
        Burn::LockBootPages,
    ] {
        let refused = burn(&mut pb, &release, step, || Ok(SECRET)).expect_err("before the digest");
        assert!(
            refused.contains("it needs Burn(WriteDigest)"),
            "{step:?}: {refused}"
        );
    }
    assert_eq!(pb_model(&mut pb).raw, before, "no row changed");
}

#[test]
fn a_board_burned_for_another_release_stops() {
    let release = release();
    let mut model = BootromModel::sealed_board();
    for row in 0..16 {
        model.ecc[usize::from(DIGEST_ROW) + row] = Some(0x1234);
        model.raw[usize::from(DIGEST_ROW) + row] = 0x3f_1234;
    }
    let mut pb = Picoboot::connect(model).expect("connect");
    let stands = standing(&mut pb);
    let refused = next(&stands, &release).expect_err("another app's digest");
    assert!(refused.contains("not this release's"), "{refused}");
}

#[test]
fn a_blank_board_has_its_secret_written_and_locked_in_one_step() {
    let release = release();
    let mut pb = Picoboot::connect(BootromModel::blank_board()).expect("connect");
    assert_eq!(
        next(&standing(&mut pb), &release),
        Ok(Next::Burn(Burn::SealSecret))
    );
    burn(&mut pb, &release, Burn::SealSecret, || Ok(SECRET)).expect("written, read back, locked");
    let model = pb_model(&mut pb);
    assert_eq!(model.raw[usize::from(lock1(48))], SECRET_LOCK);
    assert_eq!(model.ecc[usize::from(SECRET_ROW)], Some(0x5c5c));
    assert_eq!(standing(&mut pb).secret, SecretPage::Sealed);
    assert_eq!(
        next(&standing(&mut pb), &release),
        Ok(Next::Burn(Burn::WriteDigest))
    );
}

#[test]
fn a_secret_written_and_never_locked_stops_the_procedure() {
    let mut model = BootromModel::blank_board();
    model.ecc[usize::from(SECRET_ROW)] = Some(0x0101);
    model.raw[usize::from(SECRET_ROW)] = 0x3f_0101;
    let mut pb = Picoboot::connect(model).expect("connect");
    let otp = OtpReading::read(&mut pb).expect("read");
    let refused = Standing::read(&mut pb, &otp).expect_err("a page this procedure did not seal");
    assert!(refused.contains("neither blank nor sealed"), "{refused}");
    let refused = check_blank(&otp).expect_err("not blank either");
    assert!(refused.contains("neither blank nor sealed"), "{refused}");
}

#[test]
fn a_lock_row_holding_a_bit_the_procedure_does_not_burn_is_not_blank() {
    let mut model = BootromModel::sealed_board();
    model.raw[usize::from(lock1(46))] = 0x02_0202;
    let mut pb = Picoboot::connect(model).expect("connect");
    let otp = OtpReading::read(&mut pb).expect("read");
    let refused = check_blank(&otp).expect_err("0x02 is not within the digest lock 0x1d");
    assert!(refused.contains("digest page lock"), "{refused}");
}

#[test]
fn a_refused_write_says_why_and_the_link_goes_on() {
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    pb.otp_write_raw(lock1(1), &[0x15_1515])
        .expect("bits only set");
    let refused = pb.otp_write_raw(lock1(1), &[0x01_0101]);
    assert_eq!(
        refused,
        Err(BootselError::Refused {
            command: 0x0d,
            status: 17
        }),
        "a write that would clear bits"
    );
    let row = pb
        .otp_read_raw(lock1(1), 1)
        .expect("the next command is answered");
    assert_eq!(row, vec![0x15_1515]);
}

#[test]
fn the_image_on_the_board_is_read_back_whole() {
    let release = release();
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    load_image(&mut pb, &release).expect("Step 3");
    let model = pb_model(&mut pb);
    let len = release.image.len();
    assert_eq!(&model.flash[..len], release.image.as_slice());
    assert!(
        model.flash[len..len.div_ceil(256) * 256]
            .iter()
            .all(|b| *b == 0),
        "page padded with zeros"
    );
    model.flash[100] ^= 0xff;
    assert_eq!(
        crate::otp_burn::image_on_board(&mut pb, &release),
        Ok(crate::otp_burn::OnBoard::Differs { at: FLASH_BASE }),
        "the sector holding the changed byte"
    );
}

// ---- The board setup the wallet drives (`anchor.board.read` / `anchor.board.step`) ----

use crate::board_setup::{BoardPort, BoardSetup, Returned};
use crate::picoboot::BootselLink;
use dsm::types::proto as pb;
use dsm_sdk::bridge::AnchorBoardSetup;
use std::sync::{Arc, Mutex};

const CHIP: &str = "430ED6D919933C8E";

/// One board on USB, the same across every open, as a board stays between the wallet's calls.
#[derive(Clone)]
struct OnUsb(Arc<Mutex<BootromModel>>);

fn held(m: &Mutex<BootromModel>) -> std::sync::MutexGuard<'_, BootromModel> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl BootselLink for OnUsb {
    fn bulk_out(&mut self, data: &[u8]) -> Result<(), String> {
        held(&self.0).bulk_out(data)
    }
    fn bulk_in(&mut self, max: usize) -> Result<Vec<u8>, String> {
        held(&self.0).bulk_in(max)
    }
    fn ack_in(&mut self) -> Result<(), String> {
        held(&self.0).ack_in()
    }
    fn command_status(&mut self) -> Result<[u8; 16], String> {
        held(&self.0).command_status()
    }
    fn reset(&mut self) -> Result<(), String> {
        held(&self.0).reset()
    }
}

struct Phone {
    board: OnUsb,
}

impl BoardPort for Phone {
    type Link = OnUsb;
    fn open(&self) -> Result<(OnUsb, String), String> {
        Ok((self.board.clone(), CHIP.to_string()))
    }
    fn release(&self) -> Result<Release, String> {
        Ok(release())
    }
    fn secret(&self) -> Result<[u8; 32], String> {
        Ok(SECRET)
    }
    fn wait_for_return(&self, _chip_id: &str) -> Result<Returned, String> {
        match held(&self.board.0).last_boot {
            LastBoot::Refused => Ok(Returned::Bootsel),
            LastBoot::Ran => Ok(Returned::AsAnchor),
            LastBoot::NotYet => Err("the board never rebooted".to_string()),
        }
    }
}

fn phone_with(model: BootromModel) -> (BoardSetup<Phone>, Arc<Mutex<BootromModel>>) {
    let board = Arc::new(Mutex::new(model));
    (
        BoardSetup::new(Phone {
            board: OnUsb(board.clone()),
        }),
        board,
    )
}

fn state_of(
    answer: &pb::AnchorBoardResponse,
    kind: pb::AnchorBoardStepKind,
) -> pb::AnchorBoardStepState {
    let step = answer
        .steps
        .iter()
        .find(|s| s.kind == kind as i32)
        .expect("every step is listed");
    pb::AnchorBoardStepState::try_from(step.state).expect("a known state")
}

fn step(kind: pb::AnchorBoardStepKind, chip: &str) -> pb::AnchorBoardStepRequest {
    pb::AnchorBoardStepRequest {
        step: kind as i32,
        chip_id: chip.to_string(),
    }
}

#[test]
fn the_phone_reads_a_board_in_hand_and_offers_the_image_first() {
    use pb::AnchorBoardStepKind as K;
    use pb::AnchorBoardStepState as S;
    let (setup, _board) = phone_with(BootromModel::sealed_board());
    let answer = setup.read();
    assert_eq!(answer.refused, "", "{answer:?}");
    assert!(answer.board_connected);
    assert_eq!(answer.chip_id, CHIP);
    assert_eq!(state_of(&answer, K::LoadImage), S::Next);
    assert_eq!(
        state_of(&answer, K::SealSecret),
        S::Done,
        "kept from the earlier procedure"
    );
    assert_eq!(state_of(&answer, K::WriteDigest), S::Later);
    assert!(
        answer
            .found
            .iter()
            .any(|f| f.contains("sealed by an earlier procedure")),
        "{:?}",
        answer.found
    );
    assert!(
        answer.found.iter().any(|f| f.contains("0x40404")),
        "{:?}",
        answer.found
    );
    assert!(
        answer.steps.iter().filter(|s| s.permanent).count() == 7,
        "all but the image load"
    );
}

#[test]
fn a_step_given_another_boards_chip_id_writes_nothing() {
    let (setup, board) = phone_with(BootromModel::sealed_board());
    let before = held(&board).flash.clone();
    let answer = setup.step(&step(
        pb::AnchorBoardStepKind::LoadImage,
        "6F81D7E22D0A0558",
    ));
    assert!(
        answer.refused.contains("is not this board's"),
        "{}",
        answer.refused
    );
    assert_eq!(held(&board).flash, before, "the flash is as it was");
}

#[test]
fn a_step_that_is_not_the_boards_next_writes_nothing() {
    let (setup, board) = phone_with(BootromModel::sealed_board());
    let before = held(&board).raw.clone();
    let answer = setup.step(&step(pb::AnchorBoardStepKind::WriteDigest, CHIP));
    assert!(
        answer.refused.contains("not this board's next step"),
        "{}",
        answer.refused
    );
    assert_eq!(held(&board).raw, before);
}

#[test]
fn the_wallet_takes_a_sealed_board_through_every_step() {
    use pb::AnchorBoardStepKind as K;
    let (setup, board) = phone_with(BootromModel::sealed_board());
    for kind in [
        K::LoadImage,
        K::WriteDigest,
        K::LockDigest,
        K::WriteBootKey,
        K::Lockdown,
    ] {
        let answer = setup.step(&step(kind, &CHIP.to_lowercase()));
        assert_eq!(answer.refused, "", "{kind:?}: {answer:?}");
        assert!(!answer.written.is_empty(), "{kind:?} says what it wrote");
    }
    let booted = setup.step(&step(K::Boot, CHIP));
    assert_eq!(booted.refused, "", "{booted:?}");
    assert!(
        booted.written[0].contains("hold BOOTSEL"),
        "{:?}",
        booted.written
    );
    assert_eq!(held(&board).rebooted, 1);
    let last = setup.step(&step(K::LockBootPages, CHIP));
    assert_eq!(last.refused, "", "{last:?}");
    assert!(
        last.done,
        "every step done: the board goes on to its install"
    );
    assert!(last
        .steps
        .iter()
        .all(|s| s.state == pb::AnchorBoardStepState::Done as i32));
}

#[test]
fn the_rollback_flag_counts_as_the_bootrom_reads_it_by_majority() {
    let mut model = BootromModel::sealed_board();
    model.raw[crate::otp_burn::ROLLBACK_ROW as usize] = 0x1;
    model.raw[0x48] = 1 << 11;
    model.raw[0x49] = 1 << 11;
    let mut pb = Picoboot::connect(model).expect("connect");
    assert!(standing(&mut pb).rollback_recorded, "two of three copies");
    let mut model = BootromModel::sealed_board();
    model.raw[crate::otp_burn::ROLLBACK_ROW as usize] = 0x1;
    model.raw[0x48] = 1 << 11;
    let mut pb = Picoboot::connect(model).expect("connect");
    assert!(
        !standing(&mut pb).rollback_recorded,
        "one copy of three is not the flag"
    );
}

/// The release's image as flash holds it: padded with zeros to whole pages.
fn padded(release: &Release) -> Vec<u8> {
    let mut image = release.image.clone();
    image.resize(image.len().div_ceil(256) * 256, 0);
    image
}

/// A board in hand taken through its burns to the lockdown, its bootrom judging images by `signed`.
fn locked_down(signed: Option<Vec<u8>>) -> (BoardSetup<Phone>, Arc<Mutex<BootromModel>>) {
    use pb::AnchorBoardStepKind as K;
    let mut model = BootromModel::sealed_board();
    model.signed_image = signed;
    let (setup, board) = phone_with(model);
    for kind in [
        K::LoadImage,
        K::WriteDigest,
        K::LockDigest,
        K::WriteBootKey,
        K::Lockdown,
    ] {
        let answer = setup.step(&step(kind, CHIP));
        assert_eq!(answer.refused, "", "{kind:?}: {answer:?}");
    }
    (setup, board)
}

#[test]
fn a_changed_image_is_refused_and_the_signed_one_is_loaded_back() {
    use pb::AnchorBoardStepKind as K;
    let release = release();
    let (setup, board) = locked_down(Some(padded(&release)));
    let checked = setup.step(&step(K::CheckChangedImage, CHIP));
    assert_eq!(checked.refused, "", "{checked:?}");
    assert!(
        checked.written[0].contains("was refused"),
        "{:?}",
        checked.written
    );
    {
        let model = held(&board);
        assert_eq!(model.last_boot, LastBoot::Refused);
        assert_eq!(
            model.flash[..padded(&release).len()],
            padded(&release)[..],
            "the signed image is back"
        );
    }
    assert_eq!(
        state_of(&checked, K::Boot),
        pb::AnchorBoardStepState::Next,
        "the first boot is next"
    );
    let booted = setup.step(&step(K::Boot, CHIP));
    assert_eq!(booted.refused, "", "{booted:?}");
    assert_eq!(held(&board).last_boot, LastBoot::Ran);
}

#[test]
fn a_board_that_runs_a_changed_image_is_stopped() {
    use pb::AnchorBoardStepKind as K;
    // This bootrom runs whatever flash holds: secure boot is not in force.
    let (setup, _board) = locked_down(None);
    let checked = setup.step(&step(K::CheckChangedImage, CHIP));
    assert!(
        checked.refused.contains("RAN an image not as signed"),
        "{}",
        checked.refused
    );
}

#[test]
fn the_changed_image_check_waits_for_the_lockdown() {
    use pb::AnchorBoardStepKind as K;
    let release = release();
    let mut model = BootromModel::sealed_board();
    model.signed_image = Some(padded(&release));
    let (setup, board) = phone_with(model);
    assert_eq!(setup.step(&step(K::LoadImage, CHIP)).refused, "");
    let before = held(&board).flash.clone();
    let early = setup.step(&step(K::CheckChangedImage, CHIP));
    assert!(
        early.refused.contains("comes after the lockdown"),
        "{}",
        early.refused
    );
    assert_eq!(held(&board).flash, before, "nothing was written");
    assert_eq!(held(&board).rebooted, 0);
}

// ---- What the board's bootloader may write, as its bootrom guards it (the yellow board, 11-11) ----

use crate::otp_burn::{
    bootloader_may_write, lock_row_value, Bootrom, Guard, INACCESSIBLE, READ_ONLY, READ_WRITE,
};

/// The lock pages' own lock rows as the yellow board holds them (read 2026-11-11): page 62's at
/// `0x040404`, page 63's at `0x141414`, its bootloader field read-only. On an A2 bootrom that bars
/// every lock row page 63 holds, the digest page's and the rollback page's among them.
fn lock_pages_as_yellow_holds_them(mut model: BootromModel) -> BootromModel {
    model.raw[usize::from(lock1(62))] = lock_row_value(READ_WRITE, READ_ONLY, READ_WRITE);
    model.raw[usize::from(lock1(63))] = lock_row_value(READ_WRITE, READ_ONLY, READ_ONLY);
    model
}

/// The release's digest in its sixteen rows, as a board burned to Step 5 holds it.
fn digest_burned(model: &mut BootromModel, release: &Release) {
    for (i, pair) in release.digest.chunks_exact(2).enumerate() {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        model.ecc[usize::from(DIGEST_ROW) + i] = Some(value);
        model.raw[usize::from(DIGEST_ROW) + i] = u32::from(value) | 0x3f << 16;
    }
}

#[test]
fn the_bootroms_header_names_its_stepping_and_its_guard() {
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    let a2 = Bootrom::read(&mut pb).expect("an RP2350's bootrom");
    assert_eq!(a2.guard, Guard::PageItSitsIn);
    assert_eq!(
        a2.guarding_page(lock1(46)),
        63,
        "the digest page's lock row sits in page 63"
    );
    assert_eq!(a2.guarding_page(lock1(1)), 62);
    assert_eq!(a2.guarding_page(DIGEST_ROW), 46);

    let mut model = BootromModel::sealed_board();
    model.bootrom_version = 4;
    let mut pb = Picoboot::connect(model).expect("connect");
    let a4 = Bootrom::read(&mut pb).expect("an RP2350's bootrom");
    assert_eq!(a4.guard, Guard::PageItLocks);
    assert_eq!(a4.guarding_page(lock1(46)), 46, "the page the row locks");
    assert_eq!(a4.guarding_page(lock0(44)), 44);
    assert_eq!(a4.guarding_page(lock1(63)), 63);

    let mut model = BootromModel::sealed_board();
    model.bootrom_version = 7;
    let mut pb = Picoboot::connect(model).expect("connect");
    let unknown = Bootrom::read(&mut pb).expect_err("a stepping whose rule is not known");
    assert!(unknown.contains("version byte is 7"), "{unknown}");
}

#[test]
fn an_a2_board_whose_bootloader_cannot_write_a_lock_row_is_not_started() {
    use pb::AnchorBoardStepKind as K;
    use pb::AnchorBoardStepState as S;
    let (setup, board) = phone_with(BootromModel::yellow_board());
    let answer = setup.read();
    assert!(
        answer.refused.contains("cannot be finished from BOOTSEL")
            && answer.refused.contains("LockDigestPage writes row 0xfdd")
            && answer.refused.contains("page 63, the page it sits in")
            && answer.refused.contains("LockBootPages writes row 0xfd9"),
        "{}",
        answer.refused
    );
    assert_eq!(
        state_of(&answer, K::LoadImage),
        S::Blocked,
        "nothing is offered"
    );
    assert!(!answer.steps.iter().any(|s| s.state == S::Next as i32));
    for page in [
        "page 62's lock rows 0xffc and 0xffd hold 0x0 and 0x40404: the bootloader may read and write it",
        "page 63's lock rows 0xffe and 0xfff hold 0x0 and 0x141414: the bootloader may read it and not \
         write it",
    ] {
        assert!(answer.found.iter().any(|f| f == page), "{:?}", answer.found);
    }

    let flash = held(&board).flash.clone();
    let raw = held(&board).raw.clone();
    let commands = held(&board).commands.len();
    for kind in [K::LoadImage, K::WriteDigest] {
        let refused = setup.step(&step(kind, CHIP));
        assert!(
            refused.refused.starts_with("nothing was written"),
            "{kind:?}: {}",
            refused.refused
        );
    }
    let model = held(&board);
    assert_eq!(model.flash, flash, "the flash is as it was");
    assert_eq!(model.raw, raw, "no OTP row changed");
    assert!(
        !model.commands[commands..]
            .iter()
            .any(|c| *c == 0x0d || *c == 0x05),
        "no OTP or flash write was sent"
    );
}

#[test]
fn the_same_locks_on_an_a4_bootrom_guard_each_lock_row_by_its_own_page() {
    let release = release();
    let mut model = lock_pages_as_yellow_holds_them(BootromModel::blank_board());
    model.bootrom_version = 4;
    let mut pb = Picoboot::connect(model).expect("connect");
    let otp = OtpReading::read(&mut pb).expect("read");
    let a4 = Bootrom::read(&mut pb).expect("bootrom");
    let left =
        crate::otp_burn::burns_left(&Standing::read(&mut pb, &otp).expect("standing"), &release)
            .expect("burns left");
    assert_eq!(left.len(), 6, "every burn, the secret first");
    bootloader_may_write(&otp, a4, &left).expect("each lock row by the page it locks: all open");
    load_image(&mut pb, &release).expect("Step 3");
    for step in [
        Burn::SealSecret,
        Burn::WriteDigest,
        Burn::LockDigestPage,
        Burn::WriteBootKey,
        Burn::Lockdown,
    ] {
        burn(&mut pb, &release, step, || Ok(SECRET)).expect("the step burns and reads back");
    }
    assert_eq!(pb_model(&mut pb).raw[usize::from(lock1(46))], DIGEST_LOCK);
}

#[test]
fn a_board_burned_to_its_digest_stops_where_its_bootloader_cannot_go_on() {
    use pb::AnchorBoardStepKind as K;
    use pb::AnchorBoardStepState as S;
    let release = release();
    // The yellow board as it stood after Step 5 on 2026-11-11: the signed image in flash, the digest
    // burned, and its A2 bootrom refusing the digest page's lock row.
    let mut model = BootromModel::yellow_board();
    digest_burned(&mut model, &release);
    model.flash[..padded(&release).len()].copy_from_slice(&padded(&release));
    let (setup, board) = phone_with(model);
    let answer = setup.read();
    assert_eq!(state_of(&answer, K::WriteDigest), S::Done);
    assert_eq!(state_of(&answer, K::LockDigest), S::Blocked);
    assert!(
        answer.refused.contains("LockDigestPage writes row 0xfdd"),
        "{}",
        answer.refused
    );

    let raw = held(&board).raw.clone();
    let commands = held(&board).commands.len();
    let refused = setup.step(&step(K::LockDigest, CHIP));
    assert!(
        refused.refused.starts_with("nothing was written"),
        "{}",
        refused.refused
    );
    let mut pb = Picoboot::connect(OnUsb(board.clone())).expect("connect");
    let direct = burn(&mut pb, &release, Burn::LockDigestPage, || Ok(SECRET))
        .expect_err("the burn checks its own rows before it writes one");
    assert!(direct.contains("page 63"), "{direct}");
    let model = held(&board);
    assert_eq!(model.raw, raw, "no OTP row changed");
    assert!(
        !model.commands[commands..].iter().any(|c| *c == 0x0d),
        "no OTP write was sent"
    );
}

#[test]
fn a_secret_page_closed_to_the_bootloader_is_closed_on_every_bootrom() {
    // The sealed page's lock bars the bootloader from reading the page on either rule: the
    // procedure reads the secret's state from its lock row, never its rows.
    assert_eq!(
        SECRET_LOCK,
        lock_row_value(READ_ONLY, INACCESSIBLE, INACCESSIBLE)
    );
    let mut pb = Picoboot::connect(BootromModel::sealed_board()).expect("connect");
    let refused = pb.otp_read_raw(SECRET_ROW, 1);
    assert_eq!(
        refused,
        Err(BootselError::Refused {
            command: 0x8c,
            status: crate::picoboot::NOT_PERMITTED
        })
    );
}
