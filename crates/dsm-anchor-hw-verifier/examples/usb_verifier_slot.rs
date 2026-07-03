// SPDX-License-Identifier: MIT OR Apache-2.0
//! Operator bench CLI for the DSM SMT-root verifier slot, over the SAME reviewed `provisioner` code
//! the on-device SeSlotWriter runs (no bench-chip-specific hardcoding — works on a FRESH chip). It
//! reads the chip's own stpub and returns it; it does NOT gate on a known stpub, so the operator is
//! responsible for confirming the target chip identity (the runbook step).
//!
//! Subcommands (see BENCH_BURN_RUNBOOK.md):
//!   status  — NON-DESTRUCTIVE: classify slot 1 (Provisioned / Empty / Occupied) + print stpub.
//!   plan    — status + print exactly what a commit WOULD burn (fixed key, deny/allow lists). No writes.
//!   commit  — the IRREVERSIBLE burn. Refuses unless `--yes-burn-slot-1` is passed. Idempotent when
//!             already provisioned; refuses to overwrite a non-empty/wrong-key slot.
//!
//!   cargo run --manifest-path crates/dsm-anchor-hw-verifier/Cargo.toml --example usb_verifier_slot -- status /dev/cu.usbmodemdsm_anchor1
//!   cargo run ... --example usb_verifier_slot -- plan   /dev/cu.usbmodemdsm_anchor1
//!   cargo run ... --example usb_verifier_slot -- commit /dev/cu.usbmodemdsm_anchor1 --yes-burn-slot-1

// Bring-up/operator tool, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use dsm_anchor_hw_verifier::{
    commit_verifier_slot, dsm_verifier_pairing_pubkey, read_verifier_slot, VerifierSlotState,
    ALLOW_FACTORY_OPEN, DENY, VERIFIER_SLOT,
};

fn print_plan() {
    println!("--- verifier-slot burn PLAN (no writes performed) ---");
    println!("  target slot        : {VERIFIER_SLOT}  (slot 0 host NEVER touched; slots 2/3 NEVER written)");
    println!(
        "  fixed verifier pub : {:02x?}",
        dsm_verifier_pairing_pubkey()
    );
    println!("  cage = revoke SH1 access to (I_CONFIG_WRITE applied LAST):");
    for (addr, name) in DENY {
        let last = if *addr == 0x040 { "   <- LAST" } else { "" };
        println!("      0x{addr:03x}  {name}{last}");
    }
    println!("  left factory-open (SH1 keeps access):");
    for (addr, name) in ALLOW_FACTORY_OPEN {
        println!("      0x{addr:03x}  {name}");
    }
    println!("  method             : i-config only (no r-config erase); irreversible.");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args
        .iter()
        .find(|a| !a.starts_with("--") && !a.starts_with("/dev"))
        .cloned()
        .unwrap_or_else(|| "status".to_string());
    let confirmed = args.iter().any(|a| a == "--yes-burn-slot-1");
    let dev = args
        .iter()
        .find(|a| a.starts_with("/dev"))
        .cloned()
        .unwrap_or_else(usb::find_port);

    // A fresh relay channel per session: open + drain the firmware boot log, then talk libtropic.
    let make = || usb::UsbPassthrough {
        port: usb::open_and_drain(&dev),
    };

    eprintln!("[verifier-slot] cmd={cmd} port={dev}");

    match cmd.as_str() {
        "status" | "plan" => {
            match read_verifier_slot(make()) {
                Ok(VerifierSlotState::Provisioned { stpub }) => {
                    println!("[status] slot {VERIFIER_SLOT}: PROVISIONED (fixed DSM verifier key, caged read-only)");
                    println!("[status] chip stpub: {stpub:02x?}");
                    println!("[status] -> already provisioned; a commit would be a no-op.");
                }
                Ok(VerifierSlotState::Empty { stpub }) => {
                    println!(
                        "[status] slot {VERIFIER_SLOT}: EMPTY (eligible for an explicit commit)"
                    );
                    println!("[status] chip stpub: {stpub:02x?}");
                }
                Ok(VerifierSlotState::Occupied) => {
                    println!(
                        "[status] slot {VERIFIER_SLOT}: OCCUPIED by a NON-fixed key or not caged."
                    );
                    println!("[status] -> FAIL CLOSED: will NOT overwrite. Do NOT use slots 2/3 as a fallback.");
                }
                Err(e) => {
                    eprintln!("[status] read failed (fail-closed): {e:?}");
                    std::process::exit(1);
                }
            }
            if cmd == "plan" {
                println!();
                print_plan();
                println!("\n[plan] DRY-RUN only. Re-run `commit ... --yes-burn-slot-1` to burn.");
            }
        }
        "commit" => {
            if !confirmed {
                eprintln!(
                    "[commit] REFUSING: the burn is irreversible. Pass --yes-burn-slot-1 to proceed \
                     (only after the runbook checks + fresh operator approval)."
                );
                std::process::exit(2);
            }
            print_plan();
            println!(
                "\n[commit] --yes-burn-slot-1 given; running the irreversible provisioning..."
            );
            match commit_verifier_slot(make) {
                Ok((slot, stpub)) => {
                    println!("\n[PASS] slot {slot} is the caged DSM SMT-root verifier slot.");
                    println!("[disclosure] verifier_slot     = {slot}");
                    println!("[disclosure] chip_static_pubkey = {stpub:02x?}");
                }
                Err(e) => {
                    eprintln!("\n[FAIL] provisioning aborted (nothing partial trusted): {e:?}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("[verifier-slot] unknown subcommand '{other}' (use: status | plan | commit)");
            std::process::exit(2);
        }
    }
}
