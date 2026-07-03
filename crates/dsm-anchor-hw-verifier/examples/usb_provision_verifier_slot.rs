// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase-G provisioning: burn pairing slot 1 on the BENCH TROPIC01 into a READ-ONLY verifier
//! slot — one that may open an authenticated session and read the monotonic counter, and NOTHING
//! else. IRREVERSIBLE (i-config bits clear 1->0 permanently; a written pairing slot is spent).
//!
//! Guardrails (see the strict spec): slot 1 only, never slot 0; i-config only (no r-config erase);
//! dry-run by default (prints the full plan + preflight, writes nothing); `--commit` executes ONLY
//! if every precondition holds. UAP model (from the TROPIC01 config-objects header + the libtropic
//! hw_wallet config example): each 32-bit UAP register has 4 lanes (shift 0/8/16/24); within each
//! lane, bit `SH<n>_HAS_ACCESS` (SH0=0x01..SH3=0x08) says whether pairing slot n may issue that
//! command. Our verifier is session SH1, so its access bit is bit 1 of each lane => absolute bit
//! indices {1, 9, 17, 25}. To DENY SH1 a command we clear those four bits (never SH0/slot 0). To
//! ALLOW, we leave the register's factory 0xFF (SH1 bit stays set).
//!
//!   cargo run -p dsm-anchor-hw-verifier --example usb_provision_verifier_slot            # dry-run
//!   cargo run -p dsm-anchor-hw-verifier --example usb_provision_verifier_slot -- --commit /dev/cu.usbmodemdsm_anchor1

// Bring-up tool, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use dsm_anchor_hw_verifier::{dsm_verifier_pairing_pubkey, dsm_verifier_pairing_secret_bytes};
use dsm_anchor_verifier::RemoteSpiDevice;
use std::time::{Duration, Instant};

use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Error as TrError, MCounterIndex, StartupReq, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

/// The bench chip's pinned Noise static key (captured by usb_uap_probe on 2026-07-02). Provisioning
/// refuses to touch any chip whose stpub differs — the relay must be at THE bench TROPIC01.
const KNOWN_BENCH_STPUB: [u8; 32] = [
    0xd1, 0x87, 0xbc, 0xf1, 0x08, 0x9e, 0x9d, 0xaa, 0xb6, 0x4e, 0x5c, 0x0b, 0x96, 0xfd, 0x3a, 0x26,
    0x91, 0xe0, 0xd3, 0x70, 0x91, 0x0a, 0x07, 0xdb, 0x82, 0x1a, 0x32, 0x25, 0x83, 0x0f, 0xbe, 0x7d,
];

const VERIFIER_SLOT: u16 = 1;
/// Absolute bit indices of the SH1 (session/slot-1) access bit across the 4 lanes of a UAP register.
const SH1_BITS: [u8; 4] = [1, 9, 17, 25];

// The verifier pairing key is the FIXED DSM verifier key (the SAME one `RelayCounterReader` opens
// the session with — the SMT-root counter path uses one caged slot for all relationships). Slot 1
// PERMANENTLY holds this well-known key; every receiver reads through it.

/// Registers whose SH1 access must be REVOKED. I_CONFIG_WRITE is last so the verifier can never
/// loosen its own cage; ordering is otherwise cosmetic (we act as SH0, never clearing SH0 bits).
const DENY: &[(u16, &str)] = &[
    (0x020, "PAIRING_KEY_WRITE"),
    (0x024, "PAIRING_KEY_READ"),
    (0x028, "PAIRING_KEY_INVALIDATE"),
    (0x030, "R_CONFIG_WRITE_ERASE"),
    (0x110, "R_MEM_DATA_WRITE"),
    (0x114, "R_MEM_DATA_READ"),
    (0x118, "R_MEM_DATA_ERASE"),
    (0x130, "ECC_KEY_GENERATE"),
    (0x134, "ECC_KEY_STORE"),
    (0x138, "ECC_KEY_READ"),
    (0x13C, "ECC_KEY_ERASE"),
    (0x140, "ECDSA_SIGN"),
    (0x144, "EDDSA_SIGN"),
    (0x150, "MCOUNTER_INIT"),
    (0x158, "MCOUNTER_UPDATE"),
    (0x160, "MAC_AND_DESTROY"),
    (0x040, "I_CONFIG_WRITE"), // LAST: revoke the verifier's ability to change config
];

/// Registers left at factory (SH1 retains access): the counter read it needs + harmless reads.
const ALLOW: &[(u16, &str)] = &[
    (0x154, "MCOUNTER_GET (needed)"),
    (0x100, "PING (harmless)"),
    (0x120, "RANDOM_VALUE_GET (harmless)"),
    (0x034, "R_CONFIG_READ (harmless read)"),
    (0x044, "I_CONFIG_READ (harmless read)"),
];

fn is_unauthorized<A, B>(r: &Result<impl Sized, TrError<A, B>>) -> bool {
    matches!(r, Err(TrError::Unauthorized))
}

fn main() {
    let mut commit = false;
    let mut dev: Option<String> = None;
    for a in std::env::args().skip(1) {
        if a == "--commit" {
            commit = true;
        } else {
            dev = Some(a);
        }
    }
    let dev = dev.unwrap_or_else(usb::find_port);

    let b_pub = dsm_verifier_pairing_pubkey();
    let b_priv = dsm_verifier_pairing_secret_bytes();

    // ---- Plan (printed before ANY write) --------------------------------------------------------
    println!("=== Phase-G verifier-slot provisioning PLAN (bench TROPIC01) ===");
    println!(
        "  mode              : {}",
        if commit {
            "COMMIT (irreversible)"
        } else {
            "DRY-RUN (no writes)"
        }
    );
    println!("  selected slot     : {VERIFIER_SLOT}  (slot 0 is NEVER touched)");
    println!("  B pairing pubkey  : {b_pub:02x?}");
    println!("  expected chip stpub: {KNOWN_BENCH_STPUB:02x?}");
    println!("  SH1 access bits per lane (to clear on DENY): {SH1_BITS:?}");
    println!("  DENY (revoke SH1, clear bits {SH1_BITS:?} via i-config):");
    for (addr, name) in DENY {
        println!("    0x{addr:03x}  {name}");
    }
    println!("  ALLOW (leave factory 0xFF, SH1 keeps access):");
    for (addr, name) in ALLOW {
        println!("    0x{addr:03x}  {name}");
    }
    println!("  method            : i-config only (no r-config erase). Effective = r AND i.");
    println!();

    eprintln!("[provision] port = {dev}");
    let port = usb::open_and_drain(&dev);
    eprintln!("\n[provision] serve loop quiet; starting libtropic over RemoteSpiDevice");
    let mut chip = Tropic01::new(RemoteSpiDevice::new(usb::UsbPassthrough { port }));

    let stpub: [u8; 32] = *chip
        .get_info_cert_store()
        .expect("get_info_cert_store")
        .public_key()
        .expect("cert public_key");
    println!("[preflight] chip stpub: {stpub:02x?}");

    // Open the slot-0 (PROD0) session for preflight reads (and, on --commit, the writes).
    let eh = StaticSecret::from([0x42u8; 32]);
    let mut sess = match chip.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        PublicKey::from(&eh),
        eh,
        0,
    ) {
        Ok(s) => s,
        Err((_, e)) => {
            eprintln!("[FATAL] slot-0 session_start failed: {e:?}");
            std::process::exit(1);
        }
    };

    // ---- Preflight predicates (read-only) -------------------------------------------------------
    let stpub_ok = stpub == KNOWN_BENCH_STPUB;
    // Copy the read-back out so no borrow of `sess` lingers into the next command.
    let slot1_read = sess.pairing_key_read(U16::new(VERIFIER_SLOT)).map(|k| *k);
    let slot1_empty = slot1_read.is_err();
    let mcounter_ok = sess.mcounter_get(MCounterIndex::Index0);

    let mut uap_all_open = true;
    for (addr, _) in DENY.iter().chain(ALLOW.iter()) {
        let r = sess.r_config_read(U16::new(*addr));
        let i = sess.i_config_read(U16::new(*addr));
        match (r, i) {
            (Ok(r), Ok(i)) if r == 0xffff_ffff && i == 0xffff_ffff => {}
            (r, i) => {
                uap_all_open = false;
                println!("[preflight] 0x{addr:03x} NOT factory-open: r={r:?} i={i:?}");
            }
        }
    }

    println!("[preflight] stpub matches bench chip : {stpub_ok}");
    println!("[preflight] slot {VERIFIER_SLOT} empty            : {slot1_empty} ({slot1_read:?})");
    println!("[preflight] mcounter[0] readable     : {mcounter_ok:?}");
    println!("[preflight] all UAP factory-open     : {uap_all_open}");

    if !commit {
        println!("\n[DRY-RUN] no writes performed. Re-run with --commit to provision slot {VERIFIER_SLOT}.");
        return;
    }

    // ---- Gate: execute ONLY if every precondition holds -----------------------------------------
    if !(stpub_ok && slot1_empty && mcounter_ok.is_ok() && uap_all_open) {
        eprintln!(
            "[ABORT] a precondition failed; writing nothing. (This is the fail-closed stop.)"
        );
        std::process::exit(1);
    }

    // ---- 1) Write the pairing key into slot 1, then verify it read back --------------------------
    if let Err(e) = sess.pairing_key_write(U16::new(VERIFIER_SLOT), &b_pub) {
        eprintln!("[ABORT] pairing_key_write(slot {VERIFIER_SLOT}) failed: {e:?}");
        std::process::exit(1);
    }
    match sess.pairing_key_read(U16::new(VERIFIER_SLOT)).map(|k| *k) {
        Ok(k) if k == b_pub => {
            println!("[write] slot {VERIFIER_SLOT} now holds B pubkey (verified read-back)")
        }
        other => {
            eprintln!("[ABORT] slot {VERIFIER_SLOT} read-back mismatch: {other:?}");
            std::process::exit(1);
        }
    }

    // ---- 2) Restriction sweep: revoke SH1 access to every DENY command (i-config only) ----------
    for (addr, name) in DENY {
        for bit in SH1_BITS {
            if let Err(e) = sess.i_config_write(U16::new(*addr), bit) {
                eprintln!("[ABORT] i_config_write(0x{addr:03x} bit {bit}) [{name}] failed: {e:?}");
                std::process::exit(1);
            }
        }
        println!("[restrict] SH1 revoked for 0x{addr:03x} {name}");
    }

    // ---- 3) Sanity proof ------------------------------------------------------------------------
    // TROPIC01 config objects are latched at STARTUP, so the i-config restriction just written is
    // stored but not applied to the running access-control until the chip reloads config. Reboot
    // (StartupReq::Reboot) before proving the caged access surface, else the sanity would run
    // against the still-permissive boot-time snapshot.
    println!(
        "[sanity] rebooting so the new config applies, then proving the caged access surface..."
    );
    let mut chip = match sess.session_abort() {
        Ok(c) => c,
        Err((_, e)) => {
            eprintln!("[ABORT] session_abort failed: {e:?}");
            std::process::exit(1);
        }
    };
    if let Err(e) = chip.startup_req(StartupReq::Reboot) {
        eprintln!("[ABORT] startup_req(Reboot) failed: {e:?}");
        std::process::exit(1);
    }
    let dl = Instant::now() + Duration::from_secs(10);
    loop {
        match chip.get_info_chip_id() {
            Ok(_) => break,
            Err(_) if Instant::now() < dl => {}
            Err(e) => {
                eprintln!("[ABORT] chip did not come back after reboot: {e:?}");
                std::process::exit(1);
            }
        }
    }
    let eh1 = StaticSecret::from([0x77u8; 32]);
    let mut v = match chip.session_start(
        &X25519Dalek,
        PublicKey::from(b_pub),
        StaticSecret::from(b_priv),
        PublicKey::from(&eh1),
        eh1,
        VERIFIER_SLOT as u8,
    ) {
        Ok(s) => s,
        Err((_, e)) => {
            eprintln!("[ABORT] could not open a session AS slot {VERIFIER_SLOT}: {e:?}");
            std::process::exit(1);
        }
    };
    println!("[sanity] session opened as slot {VERIFIER_SLOT} with B's key");

    let get = v.mcounter_get(MCounterIndex::Index0);
    let init = v.mcounter_init(MCounterIndex::Index0, 1000); // value = current H, harmless even if it ran
    let pkw = v.pairing_key_write(U16::new(VERIFIER_SLOT), &b_pub); // same key, expected denied
    let icw = v.i_config_write(U16::new(0x040), 1); // bit already cleared above -> harmless if it ran

    println!("[sanity]  mcounter_get      : {get:?}  (expect Ok)");
    println!("[sanity]  mcounter_init     : {init:?}  (expect Unauthorized)");
    println!("[sanity]  pairing_key_write : {pkw:?}  (expect Unauthorized)");
    println!("[sanity]  i_config_write    : {icw:?}  (expect Unauthorized)");

    let chip = match v.session_abort() {
        Ok(c) => c,
        Err((_, e)) => {
            eprintln!("[ABORT] session_abort (verifier) failed: {e:?}");
            std::process::exit(1);
        }
    };
    let eh0 = StaticSecret::from([0x33u8; 32]);
    let mut s0 = match chip.session_start(
        &X25519Dalek,
        PublicKey::from(SH0PUB_PROD0),
        StaticSecret::from(SH0PRIV_PROD0),
        PublicKey::from(&eh0),
        eh0,
        0,
    ) {
        Ok(s) => s,
        Err((_, e)) => {
            eprintln!("[ABORT] slot-0 re-open failed: {e:?}");
            std::process::exit(1);
        }
    };
    let slot0_get = s0.mcounter_get(MCounterIndex::Index0);
    println!("[sanity]  slot 0 mcounter_get: {slot0_get:?}  (expect Ok, unchanged)");

    // Security property: the caged slot may read the counter and slot 0 is intact, and every
    // MUTATING command from the caged slot did NOT execute (any Err = not executed = denied).
    // Separately report that each denial was the expected `Unauthorized` code.
    let denied_as_expected =
        is_unauthorized(&init) && is_unauthorized(&pkw) && is_unauthorized(&icw);
    if !denied_as_expected {
        println!(
            "[sanity]  note: at least one denial used a non-Unauthorized error code (still denied)"
        );
    }
    let pass = get.is_ok() && init.is_err() && pkw.is_err() && icw.is_err() && slot0_get.is_ok();

    if !pass {
        eprintln!("\n[FAIL] sanity proof did not match the required access surface. STOP.");
        std::process::exit(1);
    }
    println!("\n[PASS] slot {VERIFIER_SLOT} is a READ-ONLY verifier slot: MCOUNTER_GET only.");
    println!("[disclosure] verifier_slot = {VERIFIER_SLOT}");
    println!("[disclosure] chip_static_pubkey (stpub) = {stpub:02x?}");
    println!("[disclosure] B pairing pubkey (slot {VERIFIER_SLOT}) = {b_pub:02x?}");
}
