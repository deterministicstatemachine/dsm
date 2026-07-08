// SPDX-License-Identifier: MIT OR Apache-2.0
//! Phase-3 one-COMMIT harness (host side) — FAIL-CLOSED.
//!
//! Drives an already-adopted (`u = 0`) RP2350/TROPIC01 DSM anchor over USB-CDC through EXACTLY ONE
//! offline-bearer transfer, and proves the physical counter advanced exactly once (`u: 0 -> 1`,
//! `H: H0 -> H0-1`) — using the REAL receiver-path read, never a STATUS shortcut.
//!
//! The FROM/TO counter evidence is captured by `read_live_counter` — the receiver's own
//! authenticated libtropic session opened on the CAGED VERIFIER SLOT over the raw-SPI passthrough
//! (`OP_SPI_PASSTHROUGH`). It is the identical code path the production Path-B verifier uses; the
//! only difference is the transport is this host's USB-CDC instead of the phone-to-phone BLE relay.
//!
//! ## Fail-closed by construction (COMMIT is unreachable unless every gate passes)
//!   1. the chip's anchor-id is on the operator `--allow` list (and never on `--deny`);
//!   2. the operator types the anchor-id prefix to confirm it is a USED bench chip;
//!   3. STATUS reports `u = 0` (a bench-adopted used chip);
//!   4. the CAGED-SLOT FROM read succeeds — this needs the verifier slot to be BURNED with the DSM
//!      verifier key. On an un-burned slot `session_start` fails, the read returns `Err`, the
//!      prepared record is CANCELLED, and the harness exits WITHOUT sending COMMIT;
//!   5. the FROM reading equals `H0 - u_i` (the root-committed coordinate);
//!   6. the operator types the `<prefix>-COMMIT` token to authorize exactly one counter move.
//!
//! Only then is `OP_COMMIT` sent — once. A second `OP_COMMIT` is then shown to be REFUSED by the
//! appliance, and the counter is re-read to prove it did not move again.
//!
//! RELEASE-only: a debug build refuses to run (SPHINCS+/BLE/counter timing is invalid in debug).
//!
//! DO NOT RUN until BOTH owner-gated preconditions are in place on the target used chip:
//!   * the receiver relay reader is installed, and
//!   * the verifier slot is BURNED (the DSM verifier key provisioned + caged to MCOUNTER_GET-only).
//!
//! Until then this harness fails closed at gate (4) and moves nothing — which is the point.

use std::io::Write;
use std::time::{Duration, Instant};

use anchor_core::proto::{decode_response, encode_request, pb};
use dsm_anchor_hw_verifier::{
    dsm_verifier_pairing_secret_bytes, read_live_counter, VerifierSessionCredential, VERIFIER_SLOT,
};
use dsm_anchor_verifier::{RelayError, RemoteSpiDevice, SpiRelayChannel};
use tropic01::Tropic01;
use x25519_dalek::{PublicKey, StaticSecret};

// Known-good self-test transition shape (mirrors the firmware `prepare_request` + the #574 bench).
// On-chip PREPARE is policy-agnostic (forms the cross-bound cert without validating the DSM
// transition), so these fixed values exercise prepare/commit; `prev_root` is overridden with the
// live STATUS `active_root` at call time. The receiver enforces the canonical policy in production.
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
    /// The caged verifier slot index on this chip's TROPIC01 (where the fixed DSM verifier key is
    /// provisioned). Defaults to `VERIFIER_SLOT` (1); pass `--slot N` for a chip whose verifier role
    /// was burned elsewhere (e.g. `--slot 2` when slot 1 was already spent at provisioning time).
    /// Confirm with `usb_verifier_slot status` before running. A wrong slot fails the FROM read closed.
    slot: u16,
    /// Allowed bench chip anchor-ids (Base32 Crockford). The run REFUSES unless the connected chip's
    /// anchor-id is listed — this is what stops the harness from ever committing on the sealed
    /// clean/virgin chip or any chip the operator did not explicitly designate.
    allow: Vec<String>,
    /// Explicitly denied anchor-ids (e.g. the clean fresh-birth chip). A denied chip HARD-refuses.
    deny: Vec<String>,
    /// Operator chip label for the bench log (e.g. "used chip A").
    label: Option<String>,
    /// Operator-supplied firmware build hash/commit for the bench log.
    fw_commit: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut port = None;
    let mut baud = 115_200u32;
    let mut slot = VERIFIER_SLOT;
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let mut label = None;
    let mut fw_commit = None;
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
            "--slot" => {
                slot = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--slot needs a number")?
            }
            "--allow" => allow.push(norm_id(&it.next().ok_or("--allow needs an anchor-id")?)),
            "--deny" => deny.push(norm_id(&it.next().ok_or("--deny needs an anchor-id")?)),
            "--label" => label = it.next(),
            "--fw-commit" => fw_commit = it.next(),
            "-h" | "--help" => return Err("help".to_string()),
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        port: port.ok_or("missing --port <serial device>")?,
        baud,
        slot,
        allow,
        deny,
        label,
        fw_commit,
    })
}

/// Base32 Crockford encoding (repo rule: no hex). 32-byte anchor-id -> 52-char id.
fn base32_crockford(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Normalize an operator-supplied anchor-id for comparison: uppercase, strip spaces/dashes.
fn norm_id(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase()
}

/// Read exactly `buf.len()` bytes from `port` with an 8s deadline (USB-CDC returns 0 on idle).
fn read_exact_timeout(port: &mut dyn serialport::SerialPort, buf: &mut [u8]) -> Result<(), String> {
    let mut got = 0;
    let dl = Instant::now() + Duration::from_secs(8);
    while got < buf.len() {
        if Instant::now() > dl {
            return Err("read timeout".to_string());
        }
        match port.read(&mut buf[got..]) {
            Ok(0) => {}
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// A [`SpiRelayChannel`] that BORROWS the shared appliance port, so the caged-slot verifier reads
/// (`read_live_counter`) and the appliance ops (`OP_STATUS`/`OP_PREPARE`/`OP_COMMIT`) run over the
/// one USB-CDC connection without moving ownership. Each transceive frames one raw SPI transaction
/// as `OP_SPI_PASSTHROUGH` (the firmware is a transparent SPI bridge for these bytes).
struct BorrowedRelay<'a>(&'a mut dyn serialport::SerialPort);

impl SpiRelayChannel for BorrowedRelay<'_> {
    fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
        let req = pb::ApplianceRequest {
            op: pb::Op::SpiPassthrough as i32,
            spi_payload: mosi.to_vec(),
            ..Default::default()
        };
        let body = encode_request(&req);
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(&body);
        self.0
            .write_all(&frame)
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        self.0
            .flush()
            .map_err(|e| RelayError::Transport(e.to_string()))?;

        let mut lenb = [0u8; 4];
        read_exact_timeout(self.0, &mut lenb).map_err(RelayError::Transport)?;
        let n = u32::from_le_bytes(lenb) as usize;
        if n == 0 || n > 1 << 20 {
            return Err(RelayError::Transport(format!("implausible passthrough len {n}")));
        }
        let mut respb = vec![0u8; n];
        read_exact_timeout(self.0, &mut respb).map_err(RelayError::Transport)?;
        let resp =
            decode_response(&respb).map_err(|e| RelayError::Transport(format!("decode: {e:?}")))?;
        if !resp.ok {
            return Err(RelayError::Transport(format!(
                "passthrough error code {}",
                resp.error
            )));
        }
        Ok(resp.spi_response)
    }
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
    read_exact_timeout(port, &mut len_buf).map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > 1 << 20 {
        return Err(format!("implausible response length {len}"));
    }
    let mut resp_body = vec![0u8; len];
    read_exact_timeout(port, &mut resp_body).map_err(|e| format!("read body ({len} B): {e}"))?;
    let resp = decode_response(&resp_body).map_err(|e| format!("decode: {e:?}"))?;
    if !resp.ok {
        return Err(format!("op {} failed on-chip (error {})", resp.op, resp.error));
    }
    Ok(resp)
}

/// STATUS -> `(u, H0, status, active_root)`. `u = H0 - live` is the DSM anchor coordinate; the raw
/// counter is `H = H0 - u`. `status`: 0=Ready 1=Prepared 2=Committed.
fn status(port: &mut dyn serialport::SerialPort) -> Result<(u64, u64, u32, Vec<u8>), String> {
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
        r.status,
        r.active_root,
    ))
}

/// OP_PREPARE: form the one-transfer MACANDD witness + cross-bound cert. Does NOT move the counter.
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
                authority_policy_hash: [0u8; 32].to_vec(),
            }),
            receiver_challenge: RCHAL.to_vec(),
            ..Default::default()
        },
    )
    .map(|_| ())
}

/// OP_COMMIT: move the physical counter once, erase sk_hw. Requires a Prepared record; on a chip in
/// any other state the appliance rejects it (this is what makes a second commit a no-op).
fn commit(port: &mut dyn serialport::SerialPort) -> Result<(), String> {
    roundtrip(
        port,
        &pb::ApplianceRequest {
            op: pb::Op::Commit as i32,
            ..Default::default()
        },
    )
    .map(|_| ())
}

/// OP_CANCEL: discard a prepared (uncommitted) record and return the appliance to Ready.
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

/// Read chip A's Noise static public key (`stpub`) over the passthrough, to pin the caged-slot reads
/// against. In production this pin comes from enrollment (anti-substitution across a relay); on this
/// single-host bench it is self-sourced from the one connected chip.
fn read_stpub(port: &mut dyn serialport::SerialPort) -> Result<[u8; 32], String> {
    let mut chip = Tropic01::new(RemoteSpiDevice::new(BorrowedRelay(port)));
    let cert = chip
        .get_info_cert_store()
        .map_err(|e| format!("get_info_cert_store: {e:?}"))?;
    let pk = cert
        .public_key()
        .map_err(|e| format!("cert public_key: {e:?}"))?;
    Ok(*pk)
}

/// The REAL receiver-path counter read: open B's own authenticated libtropic session on the CAGED
/// VERIFIER SLOT (fixed DSM verifier key) over the passthrough, and `mcounter_get`. This is
/// `read_live_counter` — the exact production Path-B code — driven over the borrowed USB port.
///
/// FAIL-CLOSED: if the verifier slot is not burned, `session_start` fails and this returns `Err`. No
/// STATUS fallback: the caller must treat `Err` here as "do not commit".
fn read_caged_counter(
    port: &mut dyn serialport::SerialPort,
    slot: u16,
    stpub: [u8; 32],
) -> Result<u32, String> {
    let sh = StaticSecret::from(dsm_verifier_pairing_secret_bytes());
    let cred = VerifierSessionCredential {
        slot: slot as u8,
        sh_pub: PublicKey::from(&sh).to_bytes(),
        sh_priv: sh.to_bytes(),
        pinned_static_pubkey: stpub,
    };
    let ephemeral: [u8; 32] = dsm::crypto::rng::random_bytes(32)
        .try_into()
        .map_err(|_| "CSPRNG ephemeral unavailable".to_string())?;
    read_live_counter(BorrowedRelay(port), &cred, ephemeral)
        .map_err(|e| format!("caged verifier-slot read failed: {e}"))
}

fn open(args: &Args) -> Result<Box<dyn serialport::SerialPort>, String> {
    serialport::new(&args.port, args.baud)
        .timeout(Duration::from_secs(10))
        .open()
        .map_err(|e| format!("open {}: {e}", args.port))
}

/// The chip's Base32 Crockford anchor-id, read via STATUS (non-mutating). Chip-unique + stable
/// (derived on-chip from `stpub`+`chip_id`), so it identifies the physical chip.
fn read_anchor_id(port: &mut dyn serialport::SerialPort) -> Result<String, String> {
    let r = roundtrip(
        port,
        &pb::ApplianceRequest {
            op: pb::Op::Status as i32,
            ..Default::default()
        },
    )?;
    if r.pin_anchor_id.len() != 32 {
        return Err(format!(
            "STATUS anchor-id is {} bytes (want 32) — wrong/old firmware?",
            r.pin_anchor_id.len()
        ));
    }
    Ok(base32_crockford(&r.pin_anchor_id))
}

/// Require the operator to type an EXACT token before proceeding. Fails closed on EOF or mismatch.
fn confirm(prompt: &str, expected: &str) -> Result<(), String> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read stdin: {e}"))?;
    if line.trim() != expected {
        return Err("operator confirmation did not match — aborting".to_string());
    }
    Ok(())
}

/// Gate 1+2: hard-refuse a `--deny` chip, refuse any chip not on `--allow`, then a banner + typed
/// confirmation. Returns the confirmed anchor-id.
fn gate_chip(port: &mut dyn serialport::SerialPort, args: &Args) -> Result<String, String> {
    let id = read_anchor_id(port)?;
    println!("[CHIP] anchor-id = {id}");

    if args.deny.contains(&id) {
        eprintln!("\n############################################################");
        eprintln!("#  REFUSED: anchor-id is on --deny (PROTECTED chip, e.g.   #");
        eprintln!("#  the sealed clean/virgin fresh-birth chip). Phase 3      #");
        eprintln!("#  (a real counter move) must NEVER run against it.        #");
        eprintln!("############################################################");
        return Err(format!("chip {id} is explicitly denied"));
    }
    if !args.allow.contains(&id) {
        eprintln!("\n############################################################");
        eprintln!("#  REFUSED: anchor-id is not on the --allow bench list.    #");
        eprintln!("############################################################");
        eprintln!("If this IS the designated USED bench chip (NEVER the clean/virgin chip),");
        eprintln!("re-run with:  --allow {id}");
        eprintln!("If this is the CLEAN chip, do NOT allowlist it — use --deny {id}.");
        return Err(format!("chip {id} not in the bench allowlist"));
    }

    println!("\n############################################################");
    println!("#        PHASE 3 — ONE REAL COMMIT (counter WILL move)      #");
    println!("#  Drives the designated USED chip through exactly ONE      #");
    println!("#  transfer. NEVER the sealed clean/virgin chip.            #");
    println!("############################################################");
    let prefix: String = id.chars().take(8).collect();
    confirm(
        &format!("Type the anchor-id prefix '{prefix}' to confirm this is the USED bench chip: "),
        &prefix,
    )?;
    Ok(id)
}

/// The harness build stamp: set `DSM_PHASE3_HARNESS_COMMIT=$(git rev-parse HEAD)` at build time so
/// the bench log records exactly which harness commit moved the counter.
fn harness_build() -> &'static str {
    option_env!("DSM_PHASE3_HARNESS_COMMIT")
        .unwrap_or("(unset — build with DSM_PHASE3_HARNESS_COMMIT=$(git rev-parse HEAD))")
}

/// Emit the bench-log header — the audit record for this counter-moving run.
fn bench_log(port: &mut dyn serialport::SerialPort, args: &Args, chip_id: &str) -> Result<(), String> {
    let (u, h0, _, _) = status(port)?;
    println!("\n==================== PHASE 3 BENCH LOG ====================");
    println!(
        "  chip label        : {}",
        args.label.as_deref().unwrap_or("(unlabelled — pass --label)")
    );
    println!("  anchor id         : {chip_id}");
    println!("  H0 (adopted)      : {h0}");
    println!("  pre-run u         : {u}");
    println!(
        "  firmware commit   : {}",
        args.fw_commit.as_deref().unwrap_or("(unrecorded — pass --fw-commit)")
    );
    println!("  harness commit    : {}", harness_build());
    println!("  release mode      : yes (debug_assertions=false)");
    println!(
        "  verifier slot     : {} (caged MCOUNTER_GET-only; confirm with `usb_verifier_slot status`)",
        args.slot
    );
    println!(
        "  clean chip (deny) : {}",
        if args.deny.is_empty() {
            "(none listed)".to_string()
        } else {
            args.deny.join(", ")
        }
    );
    println!("==========================================================");
    Ok(())
}

/// Phase 3: exactly ONE transfer. PREPARE -> caged FROM read -> proceed -> COMMIT -> caged TO read
/// -> assert `u:0->1` and `H:H0->H0-1` -> prove a second COMMIT is refused. Fail-closed at the FROM
/// read (gate 4): an un-burned verifier slot cancels the prepared record and returns without COMMIT.
fn phase3(
    mut port: Box<dyn serialport::SerialPort>,
    expected_id: &str,
    verifier_slot: u16,
) -> Result<(), String> {
    println!("\n== Phase 3: one-COMMIT transfer (real caged FROM/TO reads) ==");
    println!("  caged verifier slot: {verifier_slot}");

    // Pre-state: must be an adopted used chip at rest (Ready, u = 0).
    let (u_i, h0_u64, st, active_root) = status(port.as_mut())?;
    if st != 0 {
        return Err(format!("appliance not Ready (status={st}); refuse"));
    }
    if u_i != 0 {
        return Err(format!("expected u=0 (bench-adopted), got u={u_i}; refuse"));
    }
    let h0: u32 = h0_u64
        .try_into()
        .map_err(|_| format!("H0 {h0_u64} exceeds u32 (impossible counter)"))?;
    println!("  pre-state: Ready, u={u_i}, H0={h0}");

    // Pin chip A's static key for the caged reads.
    let stpub = read_stpub(port.as_mut())?;

    // (sender) PREPARE — form the MACANDD witness + cert. No counter move.
    prepare(port.as_mut(), &active_root)?;
    println!("  PREPARE ok — witness/cert formed (counter not moved)");

    // (receiver) FROM read on the CAGED VERIFIER SLOT. GATE 4 — fail-closed if the slot is not burned.
    let h_pre = match read_caged_counter(port.as_mut(), verifier_slot, stpub) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("\n== FROM read (caged verifier slot {verifier_slot}) FAILED — FAIL-CLOSED ==");
            eprintln!("  {e}");
            eprintln!("  Expected when the verifier slot is NOT burned / wrong --slot / reader absent.");
            // Do not strand the appliance: cancel the abandoned (uncommitted) Prepared.
            match cancel(port.as_mut()) {
                Ok(()) => eprintln!("  prepared record CANCELLED (appliance back to Ready)"),
                Err(ce) => eprintln!("  WARNING: cancel after fail-closed did not confirm: {ce}"),
            }
            eprintln!("  NO COMMIT was sent. The counter was NOT moved. Exiting fail-closed.");
            return Ok(());
        }
    };
    let expected_from = h0 - u_i as u32; // == h0 (u_i == 0)
    if h_pre != expected_from {
        cancel(port.as_mut()).ok();
        return Err(format!(
            "FROM evidence H_pre={h_pre} != H0 - u_i = {expected_from}; refuse COMMIT (predicate breach)"
        ));
    }
    println!("  FROM: authenticated caged read H_pre={h_pre} == H0 - u_i ({expected_from}) at u={u_i}");

    // (receiver) proceed — the FROM-gated authorization. In production this is the signed
    // `BilateralBearerProceed`; on this single-host bench it is the operator authorizing exactly one
    // counter move AFTER valid FROM evidence.
    let prefix: String = expected_id.chars().take(8).collect();
    confirm(
        &format!(
            "\nFROM evidence captured at u={u_i}. This sends ONE COMMIT and moves the counter \
             u:{u_i}->{}. Type '{prefix}-COMMIT' to authorize exactly one: ",
            u_i + 1
        ),
        &format!("{prefix}-COMMIT"),
    )?;

    // (sender) COMMIT — exactly once. Reachable only after a valid FROM read.
    commit(port.as_mut())?;
    println!("  COMMIT sent (exactly one)");

    // (receiver) TO read on the caged slot — must be H0-(u_i+1) == H_pre-1.
    let h_post = read_caged_counter(port.as_mut(), verifier_slot, stpub)
        .map_err(|e| format!("TO read AFTER commit failed: {e}"))?;
    let expected_to = h0 - (u_i as u32 + 1);
    if h_post != expected_to || h_post != h_pre - 1 {
        return Err(format!(
            "TO evidence H_post={h_post} != H0-(u_i+1)={expected_to} (H_pre-1={}); \
             counter did not advance exactly once",
            h_pre - 1
        ));
    }
    println!("  TO: authenticated caged read H_post={h_post} == H0-(u_i+1) ({expected_to}) == H_pre-1");

    // Cross-check via STATUS: u advanced exactly once.
    let (u_after, _, st_after, _) = status(port.as_mut())?;
    if u_after != u_i + 1 {
        return Err(format!("STATUS u did not advance exactly once: {u_i}->{u_after}"));
    }
    println!("  STATUS: u advanced exactly once {u_i}->{u_after} (status={st_after})");

    // Refuse any second COMMIT of the same committed transition (no fresh PREPARE): the appliance
    // must reject it, and the counter must not move again.
    match commit(port.as_mut()) {
        Err(_) => println!("  second COMMIT correctly REFUSED by the appliance"),
        Ok(()) => return Err("DOUBLE-SPEND: a SECOND COMMIT succeeded — ABORT".to_string()),
    }
    let h_after2 = read_caged_counter(port.as_mut(), verifier_slot, stpub)
        .map_err(|e| format!("post-refusal read failed: {e}"))?;
    if h_after2 != h_post {
        return Err(format!(
            "counter moved on a refused 2nd commit: {h_post}->{h_after2} — ABORT"
        ));
    }
    println!("  counter stable after refused 2nd COMMIT: H remained {h_post}");

    println!(
        "\nPHASE 3 COMPLETE: exactly one transfer committed. u:{u_i}->{u_after}, H:{h_pre}->{h_post}."
    );
    println!("Second commit refused; counter moved exactly once. STOP.");
    Ok(())
}

fn run() -> Result<(), String> {
    // RELEASE-ONLY. Debug SPHINCS+/BLE/counter timing is invalid; never touch a chip from debug.
    if cfg!(debug_assertions) {
        return Err(
            "FATAL: debug build. Build and run in --release only (debug SPHINCS+/BLE/counter timing \
             is invalid). `cargo build --release`."
                .to_string(),
        );
    }
    const USAGE: &str =
        "usage: phase3-one-commit --port <serial> --allow <anchor-id> [--slot N] [--deny <id> ...] \
                         [--label \"used chip A\"] [--fw-commit <hash>] [--baud 115200]\n  \
                         Sends EXACTLY ONE COMMIT after a real caged-slot FROM read. Fails closed \
                         (no COMMIT) if the caged read at --slot N (default 1) does not succeed at H0.";
    let args = parse_args().map_err(|e| {
        if e == "help" {
            USAGE.to_string()
        } else {
            format!("{e}\n{USAGE}")
        }
    })?;

    println!(
        "[BUILD] mode=release debug_assertions=false hw=production harness={}",
        harness_build()
    );
    println!("[PHASE3] one-COMMIT harness: exactly ONE transfer, real caged FROM/TO reads, no STATUS shortcut.");
    println!("[PHASE3] port={} baud={}", args.port, args.baud);

    let mut port = open(&args)?;
    let chip_id = gate_chip(port.as_mut(), &args)?;
    bench_log(port.as_mut(), &args, &chip_id)?;
    println!("[CHIP] confirmed USED bench chip {chip_id} — running Phase 3");
    phase3(port, &chip_id, args.slot)?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\nphase3-one-commit: {e}");
        std::process::exit(if e.starts_with("FATAL") { 2 } else { 1 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_crockford_is_stable_and_alphabet_clean() {
        // 0xFF = 11111 111 -> 'Z' (idx 31) then 111 padded to 11100 -> 'W' (idx 28).
        assert_eq!(base32_crockford(&[0xFF]), "ZW");
        let z = base32_crockford(&[0u8; 32]);
        assert_eq!(z.len(), 52);
        assert!(z.chars().all(|c| c == '0'));
        let v: Vec<u8> = (0u8..32).collect();
        assert_eq!(base32_crockford(&v), base32_crockford(&v));
        assert!(base32_crockford(&v)
            .chars()
            .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
    }

    #[test]
    fn norm_id_uppercases_and_strips_spaces_dashes() {
        assert_eq!(norm_id(" ab-cd ef "), "ABCDEF");
        assert_eq!(norm_id("Z0-Z0"), "Z0Z0");
    }

    /// The caged-slot credential the FROM/TO reads authenticate with is the FIXED DSM verifier key on
    /// the caged verifier slot — not a per-relationship or host-supplied key.
    #[test]
    fn from_to_reads_use_the_fixed_caged_verifier_key() {
        let sh = StaticSecret::from(dsm_verifier_pairing_secret_bytes());
        let cred = VerifierSessionCredential {
            slot: VERIFIER_SLOT as u8,
            sh_pub: PublicKey::from(&sh).to_bytes(),
            sh_priv: sh.to_bytes(),
            pinned_static_pubkey: [0u8; 32],
        };
        // The slot is the caged verifier slot, and the pubkey is the well-known DSM verifier pubkey.
        assert_eq!(cred.slot, VERIFIER_SLOT as u8);
        assert_eq!(cred.sh_pub, dsm_anchor_hw_verifier::dsm_verifier_pairing_pubkey());
    }
}
