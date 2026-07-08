// SPDX-License-Identifier: MIT OR Apache-2.0
//! Used-chip bench harness (host side).
//!
//! Drives the RP2350/TROPIC01 DSM anchor appliance over USB-CDC (the `ApplianceRequest`/
//! `ApplianceResponse` protocol, `LE32(len) ++ prost`) to run — against an ALREADY-USED chip
//! flashed with the `bench-adopt-existing-chip` firmware — the two SAFE phases that must pass
//! before any counter is ever spent:
//!
//!   Phase 1 (non-mutating adoption proof): STATUS reports `u = 0` (the used chip was adopted at
//!     its live counter as H0); repeated authenticated reads are identical; nothing commits and the
//!     counter never decrements; the adopted H0 is printed.
//!   Phase 2 (prepare/cancel proof): PREPARE exposes the FROM coordinate `= H0` (u stays 0, no
//!     counter move), CANCEL returns the appliance to Ready, a reconnect still reports `u = 0`, and
//!     the whole thing repeats — proving an abandoned `Prepared` does not strand the appliance.
//!
//! It NEVER sends COMMIT — Phase 3 (the first real decrement) is deliberately out of scope here.
//! RELEASE-only: a debug build refuses to run (SPHINCS+/BLE timing is invalid in debug).

use std::time::Duration;

use anchor_core::proto::{decode_response, encode_request, pb};

/// Known-good self-test transition shape (mirrors the firmware's `prepare_request`). The on-chip
/// PREPARE is policy-agnostic and forms the cross-bound cert without validating the DSM transition,
/// so these fixed values are sufficient to exercise prepare/cancel. `prev_root` is overridden with
/// the live STATUS `active_root` at call time so PREPARE always matches the appliance's active root.
const T_REL: [u8; 32] = [1; 32];
const T_OBJ: [u8; 32] = [2; 32];
const T_SND: [u8; 32] = [3; 32];
const T_RCV: [u8; 32] = [4; 32];
const NEXT_ROOT: [u8; 32] = [0x11; 32];
const T_PAY: [u8; 32] = [9; 32];
const T_AF: [u8; 2] = [0xAA, 0xBB];
const LEAF_OLD: [u8; 40] = [0xAB; 40];
const LEAF_NEW: [u8; 40] = [0xCD; 40];
const RCHAL: [u8; 32] = [0x55; 32];

struct Args {
    port: String,
    baud: u32,
    repeats: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut port = None;
    let mut baud = 115_200u32;
    let mut repeats = 5usize;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" | "-p" => port = it.next(),
            "--baud" => {
                baud = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--baud needs a number")?
            }
            "--repeats" => {
                repeats = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--repeats needs a number")?
            }
            "-h" | "--help" => return Err("help".to_string()),
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        port: port.ok_or("missing --port <serial device>")?,
        baud,
        repeats: repeats.max(2),
    })
}

/// One USB-CDC appliance op: `LE32(len) ++ ApplianceRequest`, then read `LE32(len) ++
/// ApplianceResponse`. Fails on a transport error, a decode error, or a chip-reported `!ok`.
fn roundtrip(
    port: &mut dyn serialport::SerialPort,
    req: &pb::ApplianceRequest,
) -> Result<pb::ApplianceResponse, String> {
    let body = encode_request(req);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    port.write_all(&frame).map_err(|e| format!("write: {e}"))?;
    port.flush().map_err(|e| format!("flush: {e}"))?;

    let mut len_buf = [0u8; 4];
    port.read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 1 << 20 {
        return Err(format!("implausible response length {len}"));
    }
    let mut resp_body = vec![0u8; len];
    port.read_exact(&mut resp_body)
        .map_err(|e| format!("read body ({len} B): {e}"))?;
    let resp = decode_response(&resp_body).map_err(|e| format!("decode: {e:?}"))?;
    if !resp.ok {
        return Err(format!(
            "op {} failed on-chip (error {})",
            resp.op, resp.error
        ));
    }
    Ok(resp)
}

/// STATUS -> `(u, H0, active_root)`. `u = H0 - live` is the DSM anchor coordinate; the raw counter is
/// `H = H0 - u`.
fn status(port: &mut dyn serialport::SerialPort) -> Result<(u64, u64, Vec<u8>), String> {
    let r = roundtrip(
        port,
        &pb::ApplianceRequest {
            op: pb::Op::Status as i32,
            ..Default::default()
        },
    )?;
    Ok((
        r.active_anchor_counter,
        r.pin_enrolled_counter,
        r.active_root,
    ))
}

fn prepare(port: &mut dyn serialport::SerialPort, prev_root: &[u8]) -> Result<(), String> {
    roundtrip(
        port,
        &pb::ApplianceRequest {
            op: pb::Op::Prepare as i32,
            transition: Some(pb::TransitionPackage {
                relationship_id: T_REL.to_vec(),
                object_id: T_OBJ.to_vec(),
                sender_device_id: T_SND.to_vec(),
                recipient_device_id: T_RCV.to_vec(),
                prev_root: prev_root.to_vec(),
                next_root: NEXT_ROOT.to_vec(),
                anchor_counter: 0,
                next_anchor_counter: 1,
                action_type: 0,
                action_fields: T_AF.to_vec(),
                payload_hash: T_PAY.to_vec(),
                old_leaf_proof: LEAF_OLD.to_vec(),
                new_leaf_proof: LEAF_NEW.to_vec(),
                // On-chip PREPARE is policy-agnostic; the receiver enforces the canonical policy. Phase
                // 2 cancels before any accept, so this value is never checked.
                authority_policy_hash: [0u8; 32].to_vec(),
            }),
            receiver_challenge: RCHAL.to_vec(),
            ..Default::default()
        },
    )
    .map(|_| ())
}

fn cancel(port: &mut dyn serialport::SerialPort) -> Result<(), String> {
    roundtrip(
        port,
        &pb::ApplianceRequest {
            op: pb::Op::Cancel as i32,
            ..Default::default()
        },
    )
    .map(|_| ())
}

fn open(args: &Args) -> Result<Box<dyn serialport::SerialPort>, String> {
    serialport::new(&args.port, args.baud)
        .timeout(Duration::from_secs(10))
        .open()
        .map_err(|e| format!("open {}: {e}", args.port))
}

/// Phase 1: non-mutating adoption proof. STATUS reports u=0, repeated authenticated reads are
/// identical, and nothing commits or decrements.
fn phase1(port: &mut dyn serialport::SerialPort, repeats: usize) -> Result<(), String> {
    println!("\n== Phase 1: non-mutating adoption proof ==");
    let (u0, h0, root0) = status(port)?;
    println!(
        "  STATUS: adopted H0 = {h0}  u = {u0}  raw counter H = {}",
        h0 - u0
    );
    if u0 != 0 {
        return Err(format!(
            "adoption FAILED: expected u = 0 (H0 = live), got u = {u0}. Did the chip get flashed with \
             the bench-adopt firmware?"
        ));
    }
    for i in 1..=repeats {
        let (u, h0_i, root_i) = status(port)?;
        if u != 0 || h0_i != h0 || root_i != root0 {
            return Err(format!(
                "read {i} DIVERGED: u={u} (want 0), H0={h0_i} (want {h0}), root_changed={}",
                root_i != root0
            ));
        }
    }
    println!(
        "  {repeats} repeated authenticated reads identical: u stayed 0, H0 stayed {h0}, root stable"
    );
    println!("  no COMMIT sent, no decrement: raw counter H remained {h0}");
    println!("  Phase 1 PASS");
    Ok(())
}

/// Phase 2: prepare/cancel proof. PREPARE exposes FROM = H0 without moving the counter, CANCEL
/// returns to Ready, a reconnect still shows u=0, and it repeats.
fn phase2(port_box: &mut Box<dyn serialport::SerialPort>, args: &Args) -> Result<(), String> {
    println!("\n== Phase 2: prepare/cancel proof (no counter movement) ==");
    let (_, h0, _) = status(port_box.as_mut())?;
    for round in 1..=2 {
        let prev_root = status(port_box.as_mut())?.2;
        prepare(port_box.as_mut(), &prev_root)?;
        let (u_prep, h0_prep, _) = status(port_box.as_mut())?;
        if u_prep != 0 || h0_prep != h0 {
            return Err(format!(
                "round {round}: after PREPARE expected u=0 (FROM = H0 = {h0}), got u={u_prep}, H0={h0_prep}"
            ));
        }
        println!(
            "  round {round}: PREPARE ok — FROM coordinate = H0 = {h0}, u = 0 (no counter move)"
        );

        cancel(port_box.as_mut())?;
        let (u_cancel, _, _) = status(port_box.as_mut())?;
        if u_cancel != 0 {
            return Err(format!(
                "round {round}: after CANCEL expected u=0, got u={u_cancel}"
            ));
        }

        // Reconnect: drop + reopen the USB-CDC port and confirm the abandoned Prepared did not strand
        // the appliance or move the counter.
        std::thread::sleep(Duration::from_millis(300));
        *port_box = open(args)?;
        let (u_re, h0_re, _) = status(port_box.as_mut())?;
        if u_re != 0 || h0_re != h0 {
            return Err(format!(
                "round {round}: after CANCEL + reconnect expected u=0 & H0={h0}, got u={u_re}, H0={h0_re} \
                 (abandoned Prepared stranded the appliance or moved the counter)"
            ));
        }
        println!(
            "  round {round}: CANCEL + reconnect ok — appliance back to Ready, u = 0, H0 unchanged"
        );
    }
    println!("  Phase 2 PASS");
    Ok(())
}

fn run() -> Result<(), String> {
    // RELEASE-ONLY. Debug SPHINCS+/BLE timing is invalid; never touch a chip from a debug build.
    if cfg!(debug_assertions) {
        return Err(
            "FATAL: debug build. Build and run in --release only (debug SPHINCS+/BLE timing is \
             invalid). `cargo build --release`."
                .to_string(),
        );
    }
    let args = parse_args().map_err(|e| {
        if e == "help" {
            "usage: used-chip-bench --port <serial> [--baud 115200] [--repeats 5]".to_string()
        } else {
            format!("{e}\nusage: used-chip-bench --port <serial> [--baud 115200] [--repeats 5]")
        }
    })?;

    println!("[BUILD] mode=release debug_assertions=false hw=production");
    println!(
        "[BENCH] used-chip harness: Phases 1-2 only (NON-mutating + prepare/cancel). No COMMIT."
    );
    println!(
        "[BENCH] port={} baud={} repeats={}",
        args.port, args.baud, args.repeats
    );

    let mut port = open(&args)?;
    phase1(port.as_mut(), args.repeats)?;
    phase2(&mut port, &args)?;

    println!(
        "\nALL SAFE PHASES PASSED. The used chip is adopted (u=0), reads are stable, and abandoned"
    );
    println!(
        "Prepared cancels cleanly — no counter was spent. Phase 3 (first real commit) is next,"
    );
    println!("and only after the receiver relay reader + verifier-slot burn are in place.");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\nused-chip-bench: {e}");
        std::process::exit(if e.starts_with("FATAL") { 2 } else { 1 });
    }
}
