// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase-G hardware probe: dump the TROPIC01 User Access Privileges (UAP) state that decides
//! whether a READ-ONLY verifier pairing slot can be provisioned on this chip.
//!
//! Read-only — performs NO writes. Over the existing `OP_SPI_PASSTHROUGH` firmware it:
//!   1. reads chip id + Noise static key (`stpub`),
//!   2. opens the authenticated L3 session (PROD0 slot 0),
//!   3. dumps `r_config` and `i_config` for every UAP register (effective = r AND i) — the
//!      per-byte lanes carry per-pairing-slot permission bits, so these values answer: can a
//!      new pairing slot be granted MCOUNTER_GET while being denied MCOUNTER_INIT/UPDATE,
//!      PAIRING_KEY_*, MAC_AND_DESTROY, ECC/R_MEM/config ops (i-config bits clear 1->0
//!      irreversibly, so a restriction needs the bit to still be 1 in r-config AND i-config)?
//!   4. reports pairing-key slot occupancy (slots 0-3) via `pairing_key_read`,
//!   5. reads mcounter 0 for reference.
//!
//! Run with a board attached: `cargo run -p dsm-anchor-hw-verifier --example usb_uap_probe`

// Bring-up example, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use dsm_anchor_verifier::RemoteSpiDevice;
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

/// The full APPLICATION_CO UAP register map (tropic01_application_co.h).
const UAP_REGS: &[(u16, &str)] = &[
    (0x20, "PAIRING_KEY_WRITE"),
    (0x24, "PAIRING_KEY_READ"),
    (0x28, "PAIRING_KEY_INVALIDATE"),
    (0x30, "R_CONFIG_WRITE_ERASE"),
    (0x34, "R_CONFIG_READ"),
    (0x40, "I_CONFIG_WRITE"),
    (0x44, "I_CONFIG_READ"),
    (0x100, "PING"),
    (0x110, "R_MEM_DATA_WRITE"),
    (0x114, "R_MEM_DATA_READ"),
    (0x118, "R_MEM_DATA_ERASE"),
    (0x120, "RANDOM_VALUE_GET"),
    (0x130, "ECC_KEY_GENERATE"),
    (0x134, "ECC_KEY_STORE"),
    (0x138, "ECC_KEY_READ"),
    (0x13C, "ECC_KEY_ERASE"),
    (0x140, "ECDSA_SIGN"),
    (0x144, "EDDSA_SIGN"),
    (0x150, "MCOUNTER_INIT"),
    (0x154, "MCOUNTER_GET"),
    (0x158, "MCOUNTER_UPDATE"),
    (0x160, "MAC_AND_DESTROY"),
];

fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(usb::find_port);
    eprintln!("[usb_uap_probe] port = {dev}");
    let port = usb::open_and_drain(&dev);
    eprintln!("\n[usb_uap_probe] serve loop quiet; starting libtropic over RemoteSpiDevice");

    let channel = usb::UsbPassthrough { port };
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));

    let chip_id = chip.get_info_chip_id().expect("get_info_chip_id");
    println!("[1] chip id: {chip_id:02x?}");
    let stpub: [u8; 32] = *chip
        .get_info_cert_store()
        .expect("get_info_cert_store")
        .public_key()
        .expect("cert public_key");
    println!("[2] chip Noise static key (stpub): {stpub:02x?}");

    let ehpriv = StaticSecret::from([0x42u8; 32]);
    let ehpub = PublicKey::from(&ehpriv);
    let mut session = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(SH0PUB_PROD0),
            StaticSecret::from(SH0PRIV_PROD0),
            ehpub,
            ehpriv,
            0,
        )
        .map_err(|(_, e)| e)
        .expect("session_start (PROD0 slot 0)");
    println!("[3] authenticated L3 session established (pairing slot 0)");

    println!("[4] UAP registers — effective permission = r_config AND i_config, per bit:");
    println!(
        "    {:<24} {:>10}  {:>10}  {:>10}",
        "register", "r_config", "i_config", "effective"
    );
    for (addr, name) in UAP_REGS {
        let r = session.r_config_read(U16::new(*addr));
        let i = session.i_config_read(U16::new(*addr));
        match (r, i) {
            (Ok(r), Ok(i)) => println!(
                "    {:<24} 0x{r:08x}  0x{i:08x}  0x{:08x}",
                format!("{name} (0x{addr:03x})"),
                r & i
            ),
            (r, i) => println!(
                "    {:<24} r={r:?} i={i:?}",
                format!("{name} (0x{addr:03x})")
            ),
        }
    }

    println!("[5] pairing-key slot occupancy:");
    for slot in 0u16..4 {
        match session.pairing_key_read(U16::new(slot)) {
            Ok(k) => println!("    slot {slot}: OCCUPIED pubkey={k:02x?}"),
            Err(e) => println!("    slot {slot}: not readable ({e:?}) — likely empty/invalidated"),
        }
    }

    let h = session
        .mcounter_get(MCounterIndex::Index0)
        .expect("mcounter_get");
    println!("[6] mcounter[0] H = {h} (reference)");
    println!(
        "\n[usb_uap_probe] DECISION INPUT: a read-only verifier slot N needs, for slot N's bit —\n\
         MCOUNTER_GET effective 1; MCOUNTER_INIT/UPDATE, PAIRING_KEY_*, MAC_AND_DESTROY,\n\
         R_MEM/ECC/config ops effective 0 (restrict via i_config 1->0 clears if r_config lane is 1)."
    );
}
