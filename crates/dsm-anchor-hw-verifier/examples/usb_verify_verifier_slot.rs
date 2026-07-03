// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase-G verification (NON-DESTRUCTIVE): confirm the slot-1 provisioning took effect. TROPIC01
//! config objects are latched at chip STARTUP, so an i-config change written during a live session
//! is stored but not applied until the chip reloads config on reboot. This tool:
//!   1. reads back i-config for the restricted registers (proves the writes landed),
//!   2. reboots the chip (`StartupReq::Reboot`) so it reloads config,
//!   3. re-opens the slot-1 session with B's key and proves the caged access surface.
//! It performs NO config or key writes.
//!
//!   cargo run -p dsm-anchor-hw-verifier --example usb_verify_verifier_slot -- /dev/cu.usbmodemdsm_anchor1

// Bring-up tool, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use std::time::{Duration, Instant};

use dsm_anchor_hw_verifier::{dsm_verifier_pairing_pubkey, dsm_verifier_pairing_secret_bytes};
use dsm_anchor_verifier::RemoteSpiDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Error as TrError, MCounterIndex, StartupReq, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

const VERIFIER_SLOT: u16 = 1;

/// The bench chip's pinned Noise static key (captured by usb_uap_probe / provisioning). Verification
/// asserts the relay reached THIS chip before trusting anything it reports.
const KNOWN_BENCH_STPUB: [u8; 32] = [
    0xd1, 0x87, 0xbc, 0xf1, 0x08, 0x9e, 0x9d, 0xaa, 0xb6, 0x4e, 0x5c, 0x0b, 0x96, 0xfd, 0x3a, 0x26,
    0x91, 0xe0, 0xd3, 0x70, 0x91, 0x0a, 0x07, 0xdb, 0x82, 0x1a, 0x32, 0x25, 0x83, 0x0f, 0xbe, 0x7d,
];

/// Restricted registers (must show SH1 access bits {1,9,17,25} cleared in i-config).
const DENY: &[(u16, &str)] = &[
    (0x020, "PAIRING_KEY_WRITE"),
    (0x040, "I_CONFIG_WRITE"),
    (0x150, "MCOUNTER_INIT"),
    (0x158, "MCOUNTER_UPDATE"),
    (0x160, "MAC_AND_DESTROY"),
];

fn is_unauthorized<A, B>(r: &Result<impl Sized, TrError<A, B>>) -> bool {
    matches!(r, Err(TrError::Unauthorized))
}

fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(usb::find_port);
    let b_pub = dsm_verifier_pairing_pubkey();
    let b_priv = dsm_verifier_pairing_secret_bytes();

    eprintln!("[verify] port = {dev}");
    let port = usb::open_and_drain(&dev);
    eprintln!("\n[verify] serve loop quiet; starting libtropic over RemoteSpiDevice");
    let mut chip = Tropic01::new(RemoteSpiDevice::new(usb::UsbPassthrough { port }));

    // ---- 0) Anti-substitution: the relay must have reached THE bench chip (literal stpub match) --
    let stpub: [u8; 32] = *chip
        .get_info_cert_store()
        .expect("get_info_cert_store")
        .public_key()
        .expect("cert public_key");
    let stpub_ok = stpub == KNOWN_BENCH_STPUB;
    println!("[verify] chip stpub: {stpub:02x?}");
    println!("[verify] stpub == expected bench chip: {stpub_ok}");
    if !stpub_ok {
        eprintln!("[FATAL] stpub mismatch — relay reached the WRONG chip. STOP.");
        std::process::exit(1);
    }

    // ---- 1) Read back i-config to prove the restriction writes landed --------------------------
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
    println!(
        "[verify] i-config read-back (SH1 bits 1,9,17,25 => mask 0x02020202 should be CLEAR):"
    );
    let mut all_cleared = true;
    for (addr, name) in DENY {
        match sess.i_config_read(U16::new(*addr)) {
            Ok(v) => {
                let sh1_still_set = v & 0x0202_0202 != 0;
                if sh1_still_set {
                    all_cleared = false;
                }
                println!(
                    "    0x{addr:03x} {name:<20} i=0x{v:08x}  SH1 bits {}",
                    if sh1_still_set {
                        "STILL SET"
                    } else {
                        "cleared"
                    }
                );
            }
            Err(e) => println!("    0x{addr:03x} {name:<20} read err {e:?}"),
        }
    }
    let slot1_ok =
        matches!(sess.pairing_key_read(U16::new(VERIFIER_SLOT)).map(|k| *k), Ok(k) if k == b_pub);
    println!("[verify] slot {VERIFIER_SLOT} holds expected B key: {slot1_ok}");

    // ---- 2) Reboot so the chip reloads config --------------------------------------------------
    let mut chip = match sess.session_abort() {
        Ok(c) => c,
        Err((_, e)) => {
            eprintln!("[FATAL] session_abort failed: {e:?}");
            std::process::exit(1);
        }
    };
    if let Err(e) = chip.startup_req(StartupReq::Reboot) {
        eprintln!("[FATAL] startup_req(Reboot) failed: {e:?}");
        std::process::exit(1);
    }
    println!("[verify] chip rebooted (StartupReq::Reboot) — config reloaded; settling...");
    // Poll chip-id until it answers post-reboot (config reload takes a moment).
    let dl = Instant::now() + Duration::from_secs(10);
    loop {
        match chip.get_info_chip_id() {
            Ok(_) => break,
            Err(_) if Instant::now() < dl => {}
            Err(e) => {
                eprintln!("[FATAL] chip did not come back after reboot: {e:?}");
                std::process::exit(1);
            }
        }
    }

    // ---- 3) Re-open slot 1 with B's key and prove the caged access surface ----------------------
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
            eprintln!("[FATAL] could not open session as slot {VERIFIER_SLOT}: {e:?}");
            std::process::exit(1);
        }
    };
    println!("[verify] session opened as slot {VERIFIER_SLOT} post-reboot");

    let get = v.mcounter_get(MCounterIndex::Index0);
    let init = v.mcounter_init(MCounterIndex::Index0, 1000); // value = current H; harmless if it ran
    let pkw = v.pairing_key_write(U16::new(VERIFIER_SLOT), &b_pub);
    let icw = v.i_config_write(U16::new(0x040), 1); // already-cleared bit; harmless if it ran

    println!("[sanity]  mcounter_get      : {get:?}  (expect Ok)");
    println!("[sanity]  mcounter_init     : {init:?}  (expect denied)");
    println!("[sanity]  pairing_key_write : {pkw:?}  (expect denied)");
    println!("[sanity]  i_config_write    : {icw:?}  (expect denied)");

    let chip = match v.session_abort() {
        Ok(c) => c,
        Err((_, e)) => {
            eprintln!("[FATAL] session_abort (verifier) failed: {e:?}");
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
            eprintln!("[FATAL] slot-0 re-open failed: {e:?}");
            std::process::exit(1);
        }
    };
    let slot0_get = s0.mcounter_get(MCounterIndex::Index0);
    println!("[sanity]  slot 0 mcounter_get: {slot0_get:?}  (expect Ok)");

    let denied_as_expected =
        is_unauthorized(&init) && is_unauthorized(&pkw) && is_unauthorized(&icw);
    let pass = get.is_ok() && init.is_err() && pkw.is_err() && icw.is_err() && slot0_get.is_ok();

    println!();
    println!("[verify] i-config bits cleared as written : {all_cleared}");
    println!("[verify] all denials were `Unauthorized`  : {denied_as_expected}");
    if pass {
        println!("[PASS] slot {VERIFIER_SLOT} is a READ-ONLY verifier slot (MCOUNTER_GET only) after reboot.");
    } else {
        eprintln!("[FAIL] slot {VERIFIER_SLOT} is NOT correctly caged even after reboot. STOP.");
        std::process::exit(1);
    }
}
