// SPDX-License-Identifier: MIT OR Apache-2.0
//! The burn procedure against a model of the board's bootloader that keeps OTP's rules
//! ([`crate::bootrom_model`]): the boards in hand as they stood on 2026-11-11, burned from the phone.

use crate::bootrom_model::BootromModel;
use crate::otp_burn::{
    burn, check_blank, load_image, lock1, next, Burn, Hash32, Next, OtpReading, SecretPage,
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

use crate::board_setup::{BoardPort, BoardSetup};
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
fn the_wallet_takes_a_board_in_hand_through_every_step() {
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
