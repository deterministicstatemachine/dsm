// SPDX-License-Identifier: MIT OR Apache-2.0
//! Operator bench CLI for the DSM SMT-root verifier slot, over the SAME reviewed `provisioner` code
//! the on-device SeSlotWriter runs (no bench-chip-specific hardcoding — works on a FRESH or a dev
//! chip whose lower slot is spent). It reads the chip's own stpub and returns it; it does NOT gate on
//! a known stpub, so the operator confirms the target chip identity (runbook step 2).
//!
//! The verifier ROLE is a single fixed key; its INDEX is chosen explicitly with `--slot N` (1..=3;
//! e.g. `--slot 2` on a dev chip whose slot 1 is spent). Slot 0 (host) is never a verifier slot.
//!
//! Subcommands (see BENCH_BURN_RUNBOOK.md):
//!   status    [--slot N]  — NON-DESTRUCTIVE. With --slot: classify that index. Without: SCAN 1..=3
//!                           and report where the role is provisioned (or none).
//!   preflight  --slot N   — NON-DESTRUCTIVE dry-run of the ENTIRE burn gate on the real chip: proves
//!                           slot N is SlotEmpty, the counter reads, and the UAP is factory-open, and
//!                           prints exactly what a commit WOULD burn. Writes nothing.
//!   commit     --slot N --yes-burn-slot-N   — the IRREVERSIBLE burn. The confirm flag MUST name the
//!                           SAME slot as --slot (a mismatch is refused). Idempotent if already
//!                           provisioned; refuses to overwrite a non-empty slot.
//!
//!   cargo run --manifest-path crates/dsm-anchor-hw-verifier/Cargo.toml --example usb_verifier_slot -- status /dev/cu.usbmodemdsm_anchor1
//!   cargo run ... --example usb_verifier_slot -- preflight --slot 2 /dev/cu.usbmodemdsm_anchor1
//!   cargo run ... --example usb_verifier_slot -- commit --slot 2 --yes-burn-slot-2 /dev/cu.usbmodemdsm_anchor1

// Bring-up/operator tool, not a production path: fail loudly at the console.
#![allow(clippy::disallowed_methods)]

#[path = "shared/usb.rs"]
mod usb;

use dsm_anchor_hw_verifier::{
    commit_verifier_slot, dsm_verifier_pairing_pubkey, find_provisioned_slot, init_counter_max,
    preflight_verifier_slot, read_counter, read_verifier_slot, VerifierSlotState,
    ALLOW_FACTORY_OPEN, DENY, MCOUNTER_MAX, VERIFIER_SLOT_CANDIDATES,
};

fn print_plan(slot: u16) {
    println!("--- verifier-slot burn PLAN (no writes performed) ---");
    println!(
        "  target slot        : {slot}  (slot 0 host NEVER touched; other slots NEVER written)"
    );
    println!(
        "  fixed verifier pub : {:02x?}",
        dsm_verifier_pairing_pubkey()
    );
    println!("  cage = revoke slot-{slot} access to (I_CONFIG_WRITE applied LAST):");
    for (addr, name) in DENY {
        let last = if *addr == 0x040 { "   <- LAST" } else { "" };
        println!("      0x{addr:03x}  {name}{last}");
    }
    println!("  left factory-open (slot keeps access):");
    for (addr, name) in ALLOW_FACTORY_OPEN {
        println!("      0x{addr:03x}  {name}");
    }
    println!("  method             : i-config only (no r-config erase); irreversible.");
}

/// Parse `--slot N` or `--slot=N`.
fn parse_slot(args: &[String]) -> Option<u16> {
    args.windows(2)
        .find(|w| w[0] == "--slot")
        .and_then(|w| w[1].parse().ok())
        .or_else(|| {
            args.iter()
                .find_map(|a| a.strip_prefix("--slot=").and_then(|s| s.parse().ok()))
        })
}

fn require_slot(slot: Option<u16>) -> u16 {
    match slot {
        Some(s) if VERIFIER_SLOT_CANDIDATES.contains(&s) => s,
        Some(s) => {
            eprintln!("[verifier-slot] --slot {s} is not a valid verifier index (must be one of {VERIFIER_SLOT_CANDIDATES:?})");
            std::process::exit(2);
        }
        None => {
            eprintln!("[verifier-slot] this subcommand requires --slot N (one of {VERIFIER_SLOT_CANDIDATES:?})");
            std::process::exit(2);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args
        .iter()
        .find(|a| !a.starts_with("--") && !a.starts_with("/dev"))
        .cloned()
        .unwrap_or_else(|| "status".to_string());
    let slot = parse_slot(&args);
    let dev = args
        .iter()
        .find(|a| a.starts_with("/dev"))
        .cloned()
        .unwrap_or_else(usb::find_port);

    // A fresh relay channel per session: open + drain the firmware boot log, then talk libtropic.
    let make = || usb::UsbPassthrough {
        port: usb::open_and_drain(&dev),
    };

    eprintln!("[verifier-slot] cmd={cmd} slot={slot:?} port={dev}");

    match cmd.as_str() {
        "status" => match slot {
            Some(s) => {
                let s = require_slot(Some(s));
                match read_verifier_slot(s, make()) {
                    Ok(VerifierSlotState::Provisioned { stpub }) => {
                        println!("[status] slot {s}: PROVISIONED (fixed DSM verifier key, caged read-only)");
                        println!("[status] chip stpub: {stpub:02x?}");
                    }
                    Ok(VerifierSlotState::Empty { stpub }) => {
                        println!("[status] slot {s}: EMPTY (eligible for an explicit commit)");
                        println!("[status] chip stpub: {stpub:02x?}");
                    }
                    Ok(VerifierSlotState::Occupied) => {
                        println!("[status] slot {s}: OCCUPIED by a NON-fixed key or not caged.");
                        println!("[status] -> FAIL CLOSED: will NOT overwrite. Choose a different empty slot.");
                    }
                    Err(e) => {
                        eprintln!("[status] read failed (fail-closed): {e:?}");
                        std::process::exit(1);
                    }
                }
            }
            None => match find_provisioned_slot(make) {
                Ok(Some((s, stpub))) => {
                    println!("[status] verifier role PROVISIONED at slot {s}");
                    println!("[status] chip stpub: {stpub:02x?}");
                }
                Ok(None) => println!("[status] no verifier slot provisioned on any candidate index {VERIFIER_SLOT_CANDIDATES:?}"),
                Err(e) => {
                    eprintln!("[status] scan failed (fail-closed): {e:?}");
                    std::process::exit(1);
                }
            },
        },
        "counter-status" => match read_counter(make()) {
            Ok(v) => {
                println!("[counter] mcounter[0] current : {v}");
                println!("[counter] intended max (H0)   : {MCOUNTER_MAX}");
                println!(
                    "[counter] {}",
                    if v == MCOUNTER_MAX {
                        "already at max"
                    } else {
                        "NOT at max (still a placeholder / partially spent) — counter-init sets it"
                    }
                );
            }
            Err(e) => {
                eprintln!("[counter] read failed: {e:?}");
                std::process::exit(1);
            }
        },
        "counter-init" => {
            if !args.iter().any(|a| a == "--yes-init-counter-max") {
                eprintln!("[counter-init] REFUSING: pass --yes-init-counter-max to set mcounter[0] to {MCOUNTER_MAX} (device budget). This is a slot-0 setup write; run it BEFORE the verifier-slot burn.");
                std::process::exit(2);
            }
            println!("[counter-init] setting mcounter[0] to MCOUNTER_MAX = {MCOUNTER_MAX} ...");
            match init_counter_max(make()) {
                Ok(v) => println!("[counter-init] OK: mcounter[0] read-back = {v} (== max)"),
                Err(e) => {
                    eprintln!("[counter-init] FAILED: {e:?}");
                    std::process::exit(1);
                }
            }
        }
        "preflight" => {
            let s = require_slot(slot);
            match preflight_verifier_slot(s, make()) {
                Ok(r) => {
                    println!("[preflight] slot {}: WOULD PROCEED — all read-only checks passed.", r.slot);
                    println!("[preflight] chip stpub      : {:02x?}", r.stpub);
                    println!("[preflight] mcounter[0]     : {}", r.mcounter);
                    println!("[preflight] slot {} SlotEmpty : yes  |  UAP factory-open: yes  |  counter reads: yes", r.slot);
                    println!();
                    print_plan(s);
                    println!("\n[preflight] DRY-RUN only, nothing written. If this is the intended chip + slot,");
                    println!("[preflight] run: commit --slot {s} --yes-burn-slot-{s} <port>");
                }
                Err(e) => {
                    eprintln!("[preflight] NOT eligible (nothing written): {e:?}");
                    std::process::exit(1);
                }
            }
        }
        "commit" => {
            let s = require_slot(slot);
            // The confirmation flag must name the SAME slot as --slot. A mismatch is a hard stop.
            let want = format!("--yes-burn-slot-{s}");
            let has_want = args.iter().any(|a| *a == want);
            let has_other = args
                .iter()
                .any(|a| a.starts_with("--yes-burn-slot-") && *a != want);
            if has_other {
                eprintln!("[commit] REFUSING: a --yes-burn-slot-* flag names a DIFFERENT slot than --slot {s}. Fix the mismatch.");
                std::process::exit(2);
            }
            if !has_want {
                eprintln!("[commit] REFUSING: the burn is irreversible. Pass {want} to proceed (only after preflight + fresh approval).");
                std::process::exit(2);
            }
            print_plan(s);
            println!("\n[commit] {want} given; running the irreversible provisioning of slot {s}...");
            match commit_verifier_slot(s, make) {
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
            eprintln!("[verifier-slot] unknown subcommand '{other}' (use: counter-status | counter-init | status | preflight | commit)");
            std::process::exit(2);
        }
    }
}
