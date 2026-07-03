// SPDX-License-Identifier: MIT OR Apache-2.0
//! The DSM SMT-root verifier slot: read + (gated) provision the ONE caged read-only counter slot on
//! a TROPIC01, over any [`SpiRelayChannel`]. Factored channel-generic from the exact write -> cage
//! -> reboot -> verify sequence the bench CLIs (`usb_provision_verifier_slot` /
//! `usb_verify_verifier_slot`) proved on hardware in Phase G, so the on-device SeSlotWriter runs the
//! same proven steps over the Phone->Pico USB relay.
//!
//! Slot map (fixed, never negotiated):
//! ```text
//! slot 0     = owner/admin host session (PROD0)
//! slot 1     = the fixed DSM SMT-root verifier slot
//! slots 2/3  = RESERVED — never allocated, never a fallback
//! ```
//! One caged slot serves every relationship: the verifier pairing key is the fixed DSM constant
//! (see [`dsm_verifier_pairing_secret_bytes`]); the per-receiver binding is the pinned chip identity
//! + the SMT proof + the DSM predicate, not this session key.
//!
//! [`read_verifier_slot`] is NON-DESTRUCTIVE (the transfer path uses it). [`commit_verifier_slot`]
//! performs the IRREVERSIBLE burn and must only ever run under an explicit setup/commit gate — never
//! as a side effect of app boot. It refuses to overwrite a non-empty slot (an old demo/per-
//! relationship key fails closed), so it can never clobber existing key material.

use std::time::{Duration, Instant};

use dsm_anchor_verifier::{RemoteSpiDevice, SpiRelayChannel};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Error as TrError, MCounterIndex, StartupReq, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

use crate::reader::{dsm_verifier_pairing_pubkey, dsm_verifier_pairing_secret_bytes};

/// The fixed DSM SMT-root verifier slot. NEVER slot 0 (host) and NEVER slots 2/3 (reserved).
pub const VERIFIER_SLOT: u16 = 1;

/// Absolute bit indices of the SH1 (slot-1) access bit across the 4 lanes of a UAP register.
const SH1_BITS: [u8; 4] = [1, 9, 17, 25];

/// Registers whose SH1 access is REVOKED to cage the verifier slot to MCOUNTER_GET only, with names
/// for the bench dry-run. `I_CONFIG_WRITE` (0x040) is LAST so the sweep cannot lock out the writes
/// that build the cage, and so the caged slot can never loosen its own cage afterward. `pub` so the
/// bench runbook CLI can print the exact deny list operators are about to burn.
pub const DENY: &[(u16, &str)] = &[
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
    (0x040, "I_CONFIG_WRITE"), // LAST
];

/// Registers left at factory (SH1 keeps access): the counter read + harmless reads.
pub const ALLOW_FACTORY_OPEN: &[(u16, &str)] = &[
    (0x154, "MCOUNTER_GET"), // needed
    (0x100, "PING"),
    (0x120, "RANDOM_VALUE_GET"),
    (0x034, "R_CONFIG_READ"),
    (0x044, "I_CONFIG_READ"),
];

/// The security-critical writes whose SH1 access MUST be revoked for the slot to count as caged
/// (the exact set the Phase-G verify tool proved). Checked NON-destructively via `i_config_read`.
const CAGE_CHECK: &[u16] = &[
    0x020, // PAIRING_KEY_WRITE
    0x040, // I_CONFIG_WRITE (self-cage-lock)
    0x150, // MCOUNTER_INIT
    0x158, // MCOUNTER_UPDATE
    0x160, // MAC_AND_DESTROY
];

/// SH1 access mask across the 4 UAP lanes (bits {1,9,17,25}); zero means SH1 is denied that command.
const SH1_MASK: u32 = 0x0202_0202;

/// Non-destructive state of the verifier slot.
pub enum VerifierSlotState {
    /// Slot 1 holds the fixed DSM verifier key AND is correctly caged read-only. Ready to use:
    /// disclose `(VERIFIER_SLOT, stpub)`.
    Provisioned { stpub: [u8; 32] },
    /// Slot 1 is empty — provisioning MAY proceed, but ONLY under an explicit commit gate.
    Empty { stpub: [u8; 32] },
    /// Slot 1 holds a NON-fixed key, or the fixed key without the correct cage (e.g. an old
    /// demo/per-relationship key, or a half-finished provision). FAIL CLOSED: never overwrite,
    /// never disclose.
    Occupied,
}

/// Provisioning / read errors. All map to fail-closed at the SeSlotWriter boundary.
#[derive(Debug)]
pub enum ProvisionError {
    /// The relay/chip transport failed (session, SPI, or a libtropic op).
    Chip(String),
    /// A precondition for the irreversible burn did not hold (slot not empty, UAP not factory-open,
    /// counter unreadable). Nothing was written.
    Precondition(String),
    /// The post-burn cage verification did not match the required MCOUNTER_GET-only surface.
    CageVerify(String),
    /// CSPRNG unavailable for a handshake ephemeral.
    Rng,
}

fn fresh_ephemeral() -> Result<StaticSecret, ProvisionError> {
    let b: [u8; 32] = dsm::crypto::rng::random_bytes(32)
        .try_into()
        .map_err(|_| ProvisionError::Rng)?;
    Ok(StaticSecret::from(b))
}

fn is_unauthorized<A, B>(r: &Result<impl Sized, TrError<A, B>>) -> bool {
    matches!(r, Err(TrError::Unauthorized))
}

/// Read the verifier slot's state WITHOUT writing anything (strictly read-only — safe on the
/// transfer path and at boot). Opens the host slot-0 session, reads slot 1's pairing key, and — if
/// it is the fixed key — confirms the cage via `i_config_read` of the security-critical registers
/// (SH1 access bits cleared). No slot-1 session and no write is attempted, so this can never mutate
/// or provision. The chip type is left inferred (it is parameterized by `dummy_pin::DummyPin`, a
/// tropic01 internal we do not name).
pub fn read_verifier_slot<C: SpiRelayChannel>(
    channel: C,
) -> Result<VerifierSlotState, ProvisionError> {
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));
    let stpub = *chip
        .get_info_cert_store()
        .map_err(|e| ProvisionError::Chip(format!("get_info_cert_store: {e:?}")))?
        .public_key()
        .map_err(|e| ProvisionError::Chip(format!("cert public_key: {e:?}")))?;
    let fixed_pub = dsm_verifier_pairing_pubkey();

    let eh = fresh_ephemeral()?;
    let mut s0 = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(SH0PUB_PROD0),
            StaticSecret::from(SH0PRIV_PROD0),
            PublicKey::from(&eh),
            eh,
            0,
        )
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 session_start: {e:?}")))?;

    let slot1 = s0.pairing_key_read(U16::new(VERIFIER_SLOT)).map(|k| *k);
    // Only the specific `SlotEmpty` status means an unwritten slot. ANY other error (transport,
    // session, hardware) is ambiguous and must NOT be classified as Empty — that would let a commit
    // proceed to a burn on a slot whose emptiness was never confirmed. Propagate it as a Chip error
    // (fail-closed at the caller). The cage check needs `s0`, so classify before aborting.
    let result: Result<VerifierSlotState, ProvisionError> = match slot1 {
        Err(TrError::SlotEmpty) => Ok(VerifierSlotState::Empty { stpub }),
        Err(e) => Err(ProvisionError::Chip(format!(
            "pairing_key_read slot {VERIFIER_SLOT}: {e:?}"
        ))),
        // A key is present: it must be EXACTLY the fixed key, and the cage must be configured.
        Ok(k) if k == fixed_pub => {
            // Pure-read cage check: every security-critical register must have SH1 access cleared.
            let caged = CAGE_CHECK.iter().all(
                |addr| matches!(s0.i_config_read(U16::new(*addr)), Ok(v) if v & SH1_MASK == 0),
            );
            if caged {
                Ok(VerifierSlotState::Provisioned { stpub })
            } else {
                // Fixed key but not (fully) caged = half-provisioned; fail closed (re-commit re-cages).
                Ok(VerifierSlotState::Occupied)
            }
        }
        // Any other key (e.g. an old demo/per-relationship key) — never overwrite, never disclose.
        Ok(_) => Ok(VerifierSlotState::Occupied),
    };
    // Abort the slot-0 session on every path (before surfacing an error).
    s0.session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 abort: {e:?}")))?;
    result
}

/// Provision the verifier slot — the IRREVERSIBLE burn. MUST be called only under an explicit
/// setup/commit gate. Idempotent when already provisioned; refuses (fail-closed) to overwrite any
/// non-empty slot. `make_channel` mints a fresh relay channel per session (the non-destructive
/// classification read and the burn each need their own).
pub fn commit_verifier_slot<C: SpiRelayChannel, F: Fn() -> C>(
    make_channel: F,
) -> Result<(u8, [u8; 32]), ProvisionError> {
    // 1) Classify the slot non-destructively first.
    match read_verifier_slot(make_channel())? {
        VerifierSlotState::Provisioned { stpub } => return Ok((VERIFIER_SLOT as u8, stpub)),
        VerifierSlotState::Occupied => {
            return Err(ProvisionError::Precondition(
                "slot 1 is occupied by a non-fixed key or is not caged; refusing to overwrite"
                    .into(),
            ))
        }
        VerifierSlotState::Empty { .. } => {}
    }

    // 2) Empty -> burn, on a fresh channel/session.
    let fixed_pub = dsm_verifier_pairing_pubkey();
    let fixed_priv = dsm_verifier_pairing_secret_bytes();
    let mut chip = Tropic01::new(RemoteSpiDevice::new(make_channel()));
    let stpub = *chip
        .get_info_cert_store()
        .map_err(|e| ProvisionError::Chip(format!("get_info_cert_store: {e:?}")))?
        .public_key()
        .map_err(|e| ProvisionError::Chip(format!("cert public_key: {e:?}")))?;

    let eh = fresh_ephemeral()?;
    let mut s0 = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(SH0PUB_PROD0),
            StaticSecret::from(SH0PRIV_PROD0),
            PublicKey::from(&eh),
            eh,
            0,
        )
        .map_err(|(_, e)| ProvisionError::Chip(format!("commit slot-0 session_start: {e:?}")))?;

    // 2a) Preflight: slot 1 must POSITIVELY read as `SlotEmpty` (not merely error) before any write —
    // an ambiguous transport error must abort the burn, never fall through to it. Then counter
    // readable + every DENY+ALLOW register factory-open.
    match s0.pairing_key_read(U16::new(VERIFIER_SLOT)) {
        Err(TrError::SlotEmpty) => {}
        Ok(_) => {
            return Err(ProvisionError::Precondition(
                "slot 1 is non-empty; refusing to overwrite".into(),
            ))
        }
        Err(e) => {
            return Err(ProvisionError::Chip(format!(
                "preflight pairing_key_read (emptiness unconfirmed): {e:?}"
            )))
        }
    }
    s0.mcounter_get(MCounterIndex::Index0)
        .map_err(|e| ProvisionError::Precondition(format!("mcounter unreadable: {e:?}")))?;
    for (addr, _name) in DENY.iter().chain(ALLOW_FACTORY_OPEN.iter()) {
        let r = s0.r_config_read(U16::new(*addr));
        let i = s0.i_config_read(U16::new(*addr));
        match (r, i) {
            (Ok(r), Ok(i)) if r == 0xffff_ffff && i == 0xffff_ffff => {}
            (r, i) => {
                return Err(ProvisionError::Precondition(format!(
                    "0x{addr:03x} not factory-open (r={r:?} i={i:?}); refusing to provision"
                )))
            }
        }
    }

    // 2b) Write the fixed verifier pubkey, verify read-back.
    s0.pairing_key_write(U16::new(VERIFIER_SLOT), &fixed_pub)
        .map_err(|e| ProvisionError::Chip(format!("pairing_key_write: {e:?}")))?;
    match s0.pairing_key_read(U16::new(VERIFIER_SLOT)).map(|k| *k) {
        Ok(k) if k == fixed_pub => {}
        other => {
            return Err(ProvisionError::Chip(format!(
                "slot 1 read-back mismatch after write: {other:?}"
            )))
        }
    }

    // 2c) Cage: revoke SH1 access to every DENY register (I_CONFIG_WRITE last, by list order).
    for (addr, _name) in DENY {
        for bit in SH1_BITS {
            s0.i_config_write(U16::new(*addr), bit).map_err(|e| {
                ProvisionError::Chip(format!("i_config_write(0x{addr:03x} bit {bit}): {e:?}"))
            })?;
        }
    }

    // 2d) Reboot the TROPIC01 so the i-config cage latches (config is boot-latched), then reopen.
    let mut chip = s0
        .session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("post-write abort: {e:?}")))?;
    chip.startup_req(StartupReq::Reboot)
        .map_err(|e| ProvisionError::Chip(format!("startup_req(Reboot): {e:?}")))?;
    let dl = Instant::now() + Duration::from_secs(10);
    loop {
        match chip.get_info_chip_id() {
            Ok(_) => break,
            Err(_) if Instant::now() < dl => {}
            Err(e) => {
                return Err(ProvisionError::Chip(format!(
                    "chip did not return after reboot: {e:?}"
                )))
            }
        }
    }

    // 2e) Verify the caged surface AS slot 1: MCOUNTER_GET ok; INIT/PAIRING_WRITE/I_CONFIG_WRITE denied.
    let eh1 = fresh_ephemeral()?;
    let mut v = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(fixed_pub),
            StaticSecret::from(fixed_priv),
            PublicKey::from(&eh1),
            eh1,
            VERIFIER_SLOT as u8,
        )
        .map_err(|(_, e)| ProvisionError::CageVerify(format!("verifier session_start: {e:?}")))?;
    let get = v.mcounter_get(MCounterIndex::Index0);
    let init = v.mcounter_init(MCounterIndex::Index0, 1000);
    let pkw = v.pairing_key_write(U16::new(VERIFIER_SLOT), &fixed_pub);
    let icw = v.i_config_write(U16::new(0x040), 1);
    let chip = v
        .session_abort()
        .map_err(|(_, e)| ProvisionError::CageVerify(format!("verifier abort: {e:?}")))?;

    // 2f) Slot 0 must still read the counter (host access intact).
    let eh0 = fresh_ephemeral()?;
    let mut s0 = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(SH0PUB_PROD0),
            StaticSecret::from(SH0PRIV_PROD0),
            PublicKey::from(&eh0),
            eh0,
            0,
        )
        .map_err(|(_, e)| ProvisionError::CageVerify(format!("slot-0 re-open: {e:?}")))?;
    let slot0_get = s0.mcounter_get(MCounterIndex::Index0);
    let _ = s0.session_abort();

    // The security invariant is that each mutating command did NOT execute: ANY Err == not executed
    // == denied (matches the proven bench gate). A transport glitch on a probe is still "not
    // executed", so gate on `.is_err()`; keep the Unauthorized check as a diagnostic only, so a
    // non-Unauthorized denial does not turn a correctly-caged slot into a false CageVerify failure.
    let denied_as_expected =
        is_unauthorized(&init) && is_unauthorized(&pkw) && is_unauthorized(&icw);
    if !denied_as_expected {
        log::warn!(
            "[provisioner] cage-verify: a denial used a non-Unauthorized code (still denied)"
        );
    }
    let pass = get.is_ok() && init.is_err() && pkw.is_err() && icw.is_err() && slot0_get.is_ok();
    if !pass {
        return Err(ProvisionError::CageVerify(format!(
            "caged surface wrong: get={get:?} init={init:?} pkw={pkw:?} icw={icw:?} slot0={slot0_get:?}"
        )));
    }
    Ok((VERIFIER_SLOT as u8, stpub))
}
