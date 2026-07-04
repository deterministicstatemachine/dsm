// SPDX-License-Identifier: MIT OR Apache-2.0
//! The DSM SMT-root verifier slot: read / preflight / (gated) provision the ONE caged read-only
//! counter slot on a TROPIC01, over any [`SpiRelayChannel`]. Factored channel-generic from the exact
//! write -> cage -> reboot -> verify sequence the bench proved on hardware in Phase G.
//!
//! **Role vs index.** There is exactly ONE verifier-slot ROLE (the fixed DSM verifier key — see
//! [`dsm_verifier_pairing_secret_bytes`]); it serves every relationship (the per-receiver binding is
//! the pinned chip identity + the SMT proof + the DSM predicate, not this session key). Which physical
//! pairing-key INDEX holds that role is a per-chip deployment detail: index 1 on a fresh chip, or
//! index 2/3 on a dev chip whose lower slot is already spent. The commit takes the index EXPLICITLY
//! (never auto-selected — no silent fallback); the disclosure read SCANS the candidate indices to
//! LOCATE the role. Slot 0 (host) is never a verifier slot.
//!
//! [`read_verifier_slot`] / [`find_provisioned_slot`] / [`preflight_verifier_slot`] are NON-
//! DESTRUCTIVE. [`commit_verifier_slot`] performs the IRREVERSIBLE burn and must only ever run under
//! an explicit setup/commit gate. It refuses to overwrite a non-empty slot.

use std::time::{Duration, Instant};

use dsm_anchor_verifier::{RemoteSpiDevice, SpiRelayChannel};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Error as TrError, MCounterIndex, StartupReq, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

use crate::reader::{dsm_verifier_pairing_pubkey, dsm_verifier_pairing_secret_bytes};

/// The canonical (fresh-chip) verifier-slot index. A specific dev chip may place the single verifier
/// role at another free index (e.g. 2) — pass it explicitly.
pub const VERIFIER_SLOT: u16 = 1;

/// The device's lifetime offline-bearer budget = the maximum initial value of the TROPIC01 monotonic
/// DOWN-counter (`tropic01`'s `MCOUNTER_VALUE_MAX`). `H0` (the enrolled starting counter the receiver
/// pins) is set to this at device setup; each accepted offline transfer decrements it. NOT `1000`
/// (that was only a bring-up placeholder).
pub const MCOUNTER_MAX: u32 = 0xFFFF_FFFE;

/// Pairing-key indices that MAY hold the verifier role — never slot 0 (host). The disclosure read
/// scans these to locate the role wherever it was provisioned.
pub const VERIFIER_SLOT_CANDIDATES: &[u16] = &[1, 2, 3];

/// Absolute bit indices of the SH1..SH3 access bit... note the cage always targets the SELECTED
/// slot's session bit; see `sh_mask_for`. The four lanes carry the access bit per session.
const SH_LANES: [u8; 4] = [0, 8, 16, 24];

/// Registers whose access is REVOKED to cage the verifier slot to MCOUNTER_GET only, with names for
/// the bench dry-run. `I_CONFIG_WRITE` (0x040) is LAST so the sweep cannot lock out the writes that
/// build the cage, and so the caged slot can never loosen its own cage afterward. `pub` so the bench
/// runbook CLI can print the exact deny list operators are about to burn.
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

/// Registers left at factory (the slot keeps access): the counter read + harmless reads.
pub const ALLOW_FACTORY_OPEN: &[(u16, &str)] = &[
    (0x154, "MCOUNTER_GET"), // needed
    (0x100, "PING"),
    (0x120, "RANDOM_VALUE_GET"),
    (0x034, "R_CONFIG_READ"),
    (0x044, "I_CONFIG_READ"),
];

/// The security-critical writes whose access MUST be revoked for the slot to count as caged (the set
/// the Phase-G verify tool proved). Checked NON-destructively via `i_config_read`.
const CAGE_CHECK: &[u16] = &[
    0x020, // PAIRING_KEY_WRITE
    0x040, // I_CONFIG_WRITE (self-cage-lock)
    0x150, // MCOUNTER_INIT
    0x158, // MCOUNTER_UPDATE
    0x160, // MAC_AND_DESTROY
];

/// The UAP access mask across the 4 lanes for the given pairing slot's session bit (SH`slot`). Zero
/// in the masked bits means that session is denied the command. `slot` is 1..=3 (session bit = slot).
fn sh_mask_for(slot: u16) -> u32 {
    let bit = slot as u32; // session bit index within a lane: SH1=1, SH2=2, SH3=3
    SH_LANES
        .iter()
        .fold(0u32, |m, lane| m | (1u32 << (*lane as u32 + bit)))
}

/// Non-destructive state of a specific verifier-slot index.
pub enum VerifierSlotState {
    /// Holds the fixed DSM verifier key AND is correctly caged read-only. Disclose `(index, stpub)`.
    Provisioned { stpub: [u8; 32] },
    /// Empty — provisioning MAY proceed at this index, but ONLY under an explicit commit gate.
    Empty { stpub: [u8; 32] },
    /// Holds a NON-fixed key, or the fixed key without the correct cage (e.g. an old demo/per-
    /// relationship key, or a half-finished provision). FAIL CLOSED: never overwrite, never disclose.
    Occupied,
}

/// Read-only preflight facts an operator sees BEFORE any burn.
pub struct PreflightReport {
    /// The slot index the burn would target.
    pub slot: u16,
    /// The chip's Noise static public key (its identity) — confirm this is the intended chip.
    pub stpub: [u8; 32],
    /// The current monotonic counter value (proves the counter reads).
    pub mcounter: u32,
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
    /// The requested slot index is not a valid verifier candidate (must be 1..=3, never slot 0).
    BadSlot(u16),
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

fn check_slot(slot: u16) -> Result<(), ProvisionError> {
    if VERIFIER_SLOT_CANDIDATES.contains(&slot) {
        Ok(())
    } else {
        Err(ProvisionError::BadSlot(slot))
    }
}

/// Classify a SPECIFIC verifier-slot index WITHOUT writing anything (strictly read-only). Opens the
/// host slot-0 session, reads the slot's pairing key, and — if it is the fixed key — confirms the
/// cage via `i_config_read` of the security-critical registers (the slot's access bits cleared). No
/// session as the verifier slot and no write is attempted, so this can never mutate or provision.
pub fn read_verifier_slot<C: SpiRelayChannel>(
    slot: u16,
    channel: C,
) -> Result<VerifierSlotState, ProvisionError> {
    check_slot(slot)?;
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));
    let stpub = *chip
        .get_info_cert_store()
        .map_err(|e| ProvisionError::Chip(format!("get_info_cert_store: {e:?}")))?
        .public_key()
        .map_err(|e| ProvisionError::Chip(format!("cert public_key: {e:?}")))?;
    let fixed_pub = dsm_verifier_pairing_pubkey();
    let mask = sh_mask_for(slot);

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

    let key = s0.pairing_key_read(U16::new(slot)).map(|k| *k);
    // Only the specific `SlotEmpty` status means an unwritten slot. ANY other error is ambiguous and
    // must NOT be classified as Empty (that would let a commit burn on an unconfirmed slot).
    let result: Result<VerifierSlotState, ProvisionError> = match key {
        Err(TrError::SlotEmpty) => Ok(VerifierSlotState::Empty { stpub }),
        Err(e) => Err(ProvisionError::Chip(format!(
            "pairing_key_read slot {slot}: {e:?}"
        ))),
        Ok(k) if k == fixed_pub => {
            // Pure-read cage check: every security-critical register must have this slot's access cleared.
            let caged = CAGE_CHECK
                .iter()
                .all(|addr| matches!(s0.i_config_read(U16::new(*addr)), Ok(v) if v & mask == 0));
            if caged {
                Ok(VerifierSlotState::Provisioned { stpub })
            } else {
                Ok(VerifierSlotState::Occupied)
            }
        }
        Ok(_) => Ok(VerifierSlotState::Occupied),
    };
    s0.session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 abort: {e:?}")))?;
    result
}

/// Scan the candidate indices to LOCATE the single provisioned verifier role. Returns `Some((index,
/// stpub))` for the first index that reads back as `Provisioned`, else `None`. Non-destructive.
/// `make_channel` mints a fresh relay channel per probed index.
pub fn find_provisioned_slot<C: SpiRelayChannel, F: Fn() -> C>(
    make_channel: F,
) -> Result<Option<(u16, [u8; 32])>, ProvisionError> {
    for &slot in VERIFIER_SLOT_CANDIDATES {
        if let VerifierSlotState::Provisioned { stpub } = read_verifier_slot(slot, make_channel())?
        {
            return Ok(Some((slot, stpub)));
        }
    }
    Ok(None)
}

/// Read-only dry-run of the burn's ENTIRE gating logic for `slot`, on the actual chip: the slot reads
/// back `SlotEmpty`, the counter is readable, and every deny/allow register is factory-open. Returns
/// the [`PreflightReport`] (chip identity + counter) iff a commit WOULD proceed. Writes NOTHING.
pub fn preflight_verifier_slot<C: SpiRelayChannel>(
    slot: u16,
    channel: C,
) -> Result<PreflightReport, ProvisionError> {
    check_slot(slot)?;
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));
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
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 session_start: {e:?}")))?;

    // Preflight body (read-only) inline, so the open-session chip type stays inferred.
    let report = (|| -> Result<PreflightReport, ProvisionError> {
        match s0.pairing_key_read(U16::new(slot)) {
            Err(TrError::SlotEmpty) => {}
            Ok(_) => {
                return Err(ProvisionError::Precondition(format!(
                    "slot {slot} is non-empty; refusing to burn (no overwrite)"
                )))
            }
            Err(e) => {
                return Err(ProvisionError::Chip(format!(
                    "preflight pairing_key_read slot {slot} (emptiness unconfirmed): {e:?}"
                )))
            }
        }
        let mcounter = s0
            .mcounter_get(MCounterIndex::Index0)
            .map_err(|e| ProvisionError::Precondition(format!("mcounter unreadable: {e:?}")))?;
        // The SELECTED slot must currently have FULL (factory) access at every deny/allow register,
        // so the cage is a real restriction and the slot retains the allow set. Only THIS slot's
        // access bits are checked — a lower slot already caged on the same chip (e.g. slot 1 on a dev
        // chip) leaves other lanes' bits cleared, which is irrelevant to provisioning this slot.
        let mask = sh_mask_for(slot);
        for (addr, name) in DENY.iter().chain(ALLOW_FACTORY_OPEN.iter()) {
            let r = s0.r_config_read(U16::new(*addr));
            let i = s0.i_config_read(U16::new(*addr));
            match (r, i) {
                (Ok(r), Ok(i)) if r & mask == mask && i & mask == mask => {}
                (r, i) => {
                    return Err(ProvisionError::Precondition(format!(
                    "0x{addr:03x} {name}: slot-{slot} access not factory-open (r={r:?} i={i:?}); refusing to provision"
                )))
                }
            }
        }
        Ok(PreflightReport {
            slot,
            stpub,
            mcounter,
        })
    })();
    s0.session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 abort: {e:?}")))?;
    report
}

/// Provision the verifier role at `slot` — the IRREVERSIBLE burn. MUST be called only under an
/// explicit setup/commit gate. Idempotent when `slot` already holds the fixed key + cage; refuses
/// (fail-closed) to overwrite any non-empty slot. `make_channel` mints a fresh relay channel per
/// session (the non-destructive classification read and the burn each need their own).
pub fn commit_verifier_slot<C: SpiRelayChannel, F: Fn() -> C>(
    slot: u16,
    make_channel: F,
) -> Result<(u16, [u8; 32]), ProvisionError> {
    check_slot(slot)?;
    // 1) Classify the slot non-destructively first.
    match read_verifier_slot(slot, make_channel())? {
        VerifierSlotState::Provisioned { stpub } => return Ok((slot, stpub)),
        VerifierSlotState::Occupied => {
            return Err(ProvisionError::Precondition(format!(
                "slot {slot} is occupied by a non-fixed key or is not caged; refusing to overwrite"
            )))
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

    // 2a) Preflight (positive SlotEmpty + factory-open + readable counter) — writes nothing. Inline
    // so the open-session chip type stays inferred; identical checks to `preflight_verifier_slot`.
    match s0.pairing_key_read(U16::new(slot)) {
        Err(TrError::SlotEmpty) => {}
        Ok(_) => {
            return Err(ProvisionError::Precondition(format!(
                "slot {slot} became non-empty before write; refusing to overwrite"
            )))
        }
        Err(e) => {
            return Err(ProvisionError::Chip(format!(
                "commit preflight pairing_key_read slot {slot}: {e:?}"
            )))
        }
    }
    s0.mcounter_get(MCounterIndex::Index0)
        .map_err(|e| ProvisionError::Precondition(format!("mcounter unreadable: {e:?}")))?;
    let mask = sh_mask_for(slot);
    for (addr, name) in DENY.iter().chain(ALLOW_FACTORY_OPEN.iter()) {
        let r = s0.r_config_read(U16::new(*addr));
        let i = s0.i_config_read(U16::new(*addr));
        match (r, i) {
            (Ok(r), Ok(i)) if r & mask == mask && i & mask == mask => {}
            (r, i) => {
                return Err(ProvisionError::Precondition(format!(
                    "0x{addr:03x} {name}: slot-{slot} access not factory-open (r={r:?} i={i:?}); refusing to provision"
                )))
            }
        }
    }

    // 2b) Write the fixed verifier pubkey, verify read-back.
    s0.pairing_key_write(U16::new(slot), &fixed_pub)
        .map_err(|e| ProvisionError::Chip(format!("pairing_key_write: {e:?}")))?;
    match s0.pairing_key_read(U16::new(slot)).map(|k| *k) {
        Ok(k) if k == fixed_pub => {}
        other => {
            return Err(ProvisionError::Chip(format!(
                "slot {slot} read-back mismatch after write: {other:?}"
            )))
        }
    }

    // 2c) Cage: revoke this slot's access to every DENY register (I_CONFIG_WRITE last, by list order).
    for (addr, _name) in DENY {
        for lane in SH_LANES {
            let bit = (lane as u16) + slot; // absolute bit index of SH`slot` in this lane
            s0.i_config_write(U16::new(*addr), bit as u8).map_err(|e| {
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

    // 2e) Verify the caged surface AS the verifier slot: MCOUNTER_GET ok; INIT/PAIRING_WRITE/
    // I_CONFIG_WRITE denied.
    let eh1 = fresh_ephemeral()?;
    let mut v = chip
        .session_start(
            &X25519Dalek,
            PublicKey::from(fixed_pub),
            StaticSecret::from(fixed_priv),
            PublicKey::from(&eh1),
            eh1,
            slot as u8,
        )
        .map_err(|(_, e)| ProvisionError::CageVerify(format!("verifier session_start: {e:?}")))?;
    let get = v.mcounter_get(MCounterIndex::Index0);
    let init = v.mcounter_init(MCounterIndex::Index0, 1000); // value irrelevant; expected denied
    let pkw = v.pairing_key_write(U16::new(slot), &fixed_pub);
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

    // Any Err on a mutating command == not executed == denied (matches the proven bench gate). Keep
    // the Unauthorized check only as a diagnostic so a non-Unauthorized denial does not false-fail.
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
    Ok((slot, stpub))
}

// ── Monotonic counter (the offline-bearer budget) — a SEPARATE device-setup concern from the ──────
// verifier slot. Read is non-destructive; init is the explicit budget write. Both are slot-0 ops.

/// Read `mcounter[0]` (the offline-bearer budget / current `H`) via the host slot-0 session.
/// NON-DESTRUCTIVE.
pub fn read_counter<C: SpiRelayChannel>(channel: C) -> Result<u32, ProvisionError> {
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));
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
    let v = s0
        .mcounter_get(MCounterIndex::Index0)
        .map_err(|e| ProvisionError::Chip(format!("mcounter_get: {e:?}")));
    s0.session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 abort: {e:?}")))?;
    v
}

/// Initialize `mcounter[0]` to [`MCOUNTER_MAX`] (the device's lifetime offline-bearer budget) via the
/// host slot-0 session — the explicit device-setup WRITE. Reads it back and confirms it equals
/// `MCOUNTER_MAX`, returning the read-back value. Slot 0 only (the caged verifier slot is denied
/// `mcounter_init`). MUST run only under an explicit setup gate, and BEFORE the verifier-slot cage.
pub fn init_counter_max<C: SpiRelayChannel>(channel: C) -> Result<u32, ProvisionError> {
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));
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
    s0.mcounter_init(MCounterIndex::Index0, MCOUNTER_MAX)
        .map_err(|e| ProvisionError::Chip(format!("mcounter_init(max): {e:?}")))?;
    let readback = s0
        .mcounter_get(MCounterIndex::Index0)
        .map_err(|e| ProvisionError::Chip(format!("mcounter_get after init: {e:?}")))?;
    s0.session_abort()
        .map_err(|(_, e)| ProvisionError::Chip(format!("slot-0 abort: {e:?}")))?;
    if readback != MCOUNTER_MAX {
        return Err(ProvisionError::CageVerify(format!(
            "counter read-back {readback} != MCOUNTER_MAX {MCOUNTER_MAX}"
        )));
    }
    Ok(readback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_mask_matches_the_session_bit_per_lane() {
        // Session bit N within each lane byte (SH1=bit1, SH2=bit2, SH3=bit3), 4 lanes at 0/8/16/24.
        assert_eq!(sh_mask_for(1), 0x0202_0202, "SH1 = bits {{1,9,17,25}}");
        assert_eq!(sh_mask_for(2), 0x0404_0404, "SH2 = bits {{2,10,18,26}}");
        assert_eq!(sh_mask_for(3), 0x0808_0808, "SH3 = bits {{3,11,19,27}}");
    }

    #[test]
    fn cage_sweep_bits_are_absolute_and_match_the_mask() {
        // The commit sweep writes bits (lane + slot); their OR must equal the read-path mask.
        for &slot in VERIFIER_SLOT_CANDIDATES {
            let mut swept = 0u32;
            for lane in SH_LANES {
                swept |= 1u32 << (lane as u32 + slot as u32);
            }
            assert_eq!(
                swept,
                sh_mask_for(slot),
                "sweep vs mask mismatch for slot {slot}"
            );
        }
    }

    #[test]
    fn mcounter_max_is_the_hardware_ceiling() {
        // The device budget = the TROPIC01 down-counter ceiling (tropic01 MCOUNTER_VALUE_MAX), NOT
        // the old 1000 placeholder.
        assert_eq!(MCOUNTER_MAX, 0xFFFF_FFFE);
        assert!(MCOUNTER_MAX > 1000);
    }

    #[test]
    fn only_candidate_slots_are_accepted() {
        assert!(
            check_slot(0).is_err(),
            "slot 0 (host) is never a verifier slot"
        );
        assert!(check_slot(4).is_err(), "slot 4 is out of range");
        for &s in VERIFIER_SLOT_CANDIDATES {
            assert!(check_slot(s).is_ok());
        }
    }
}
