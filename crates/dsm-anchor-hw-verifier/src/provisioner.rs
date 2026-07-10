// SPDX-License-Identifier: MIT OR Apache-2.0
//! LOCAL-chip device-setup operations (Software-Authority / Hardware-Identity): counter birth and
//! the slot-0 birth cage, over any [`SpiRelayChannel`] (bench serial CLI, or the phone's own USB
//! `OP_SPI_PASSTHROUGH` link to its own Pico). Factored channel-generic from the exact
//! write -> cage -> reboot -> verify sequence the bench proved on hardware.
//!
//! v2 removed the receiver-side verifier slot entirely (no receiver ever reads a peer's chip), so
//! all that remains is what brings a production chip to birth:
//!   1. [`init_counter_max`] — write the lifetime offline-bearer budget `H0 = MCOUNTER_MAX`.
//!   2. [`birth_cage_slot0`] — IRREVERSIBLY revoke slot-0's counter-reset + re-key + un-cage
//!      authority ([`SLOT0_BIRTH_DENY`]), making the down-counter's one-way monotonicity a
//!      hardware birth invariant.
//! [`read_counter`] is the non-destructive diagnostic read.

use std::time::{Duration, Instant};

use dsm_anchor_verifier::{RemoteSpiDevice, SpiRelayChannel};
use tropic01::keys::{SH0PRIV_PROD0, SH0PUB_PROD0};
use tropic01::{Error as TrError, MCounterIndex, StartupReq, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::little_endian::U16;

/// The device's lifetime offline-bearer budget = the maximum initial value of the TROPIC01 monotonic
/// DOWN-counter (`tropic01`'s `MCOUNTER_VALUE_MAX`). `H0` (the enrolled starting counter pinned into
/// the bundle `B`) is set to this at device setup; each committed offline transfer decrements it.
pub const MCOUNTER_MAX: u32 = 0xFFFF_FFFE;

/// The four UAP lane byte offsets; each lane carries one access bit per session (SH0..SH3).
const SH_LANES: [u8; 4] = [0, 8, 16, 24];

/// Registers REVOKED from slot 0 (SH0 / host) by the **birth burn** ([`birth_cage_slot0`]). Denying
/// `MCOUNTER_INIT` makes the monotonic counter permanently one-way: no holder of the (public) `PROD0`
/// pairing key — not a breached RP2350 partition, not a passthrough host — can ever reset `H` and
/// replay consumed offline-bearer steps. `PAIRING_KEY_WRITE`/`INVALIDATE` freeze slot 0's identity;
/// `I_CONFIG_WRITE` is LAST so the cage self-locks (the slot can never loosen its own cage). Left
/// factory-open: `MCOUNTER_UPDATE` (0x158), `MCOUNTER_GET` (0x154), `MAC_AND_DESTROY` (0x160) — the
/// appliance's runtime surface (slot 0 still has to run the appliance).
pub const SLOT0_BIRTH_DENY: &[(u16, &str)] = &[
    (0x150, "MCOUNTER_INIT"),
    (0x020, "PAIRING_KEY_WRITE"),
    (0x028, "PAIRING_KEY_INVALIDATE"),
    (0x040, "I_CONFIG_WRITE"), // LAST — self-locks the cage
];

/// The UAP access mask across the 4 lanes for the given pairing slot's session bit (SH`slot`). Zero
/// in the masked bits means that session is denied the command (session bit = slot index).
fn sh_mask_for(slot: u16) -> u32 {
    let bit = slot as u32; // session bit index within a lane: SH0=0 .. SH3=3
    SH_LANES
        .iter()
        .fold(0u32, |m, lane| m | (1u32 << (*lane as u32 + bit)))
}


/// Provisioning / read errors. All map to fail-closed at the caller.
#[derive(Debug)]
pub enum ProvisionError {
    /// The relay/chip transport failed (session, SPI, or a libtropic op).
    Chip(String),
    /// A precondition for the irreversible burn did not hold (slot not empty, UAP not factory-open,
    /// counter unreadable). Nothing was written.
    Precondition(String),
    /// The post-burn cage verification did not match the required sealed surface.
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

// ── Monotonic counter (the offline-bearer budget). Read is non-destructive; init is the ──────────
// explicit budget write. Both are slot-0 ops.

/// Read `mcounter[0]` (the offline-bearer budget / current `H`) via the host slot-0 session.
/// NON-DESTRUCTIVE.
pub fn read_counter<C: SpiRelayChannel>(channel: C) -> Result<u32, ProvisionError> {
    let chip = Tropic01::new(RemoteSpiDevice::new(channel));
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
/// `MCOUNTER_MAX`, returning the read-back value. MUST run only under an explicit setup gate, and
/// BEFORE [`birth_cage_slot0`] (which revokes `mcounter_init` forever).
pub fn init_counter_max<C: SpiRelayChannel>(channel: C) -> Result<u32, ProvisionError> {
    let chip = Tropic01::new(RemoteSpiDevice::new(channel));
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

/// The irreversible **birth burn** on slot 0 — the event that brings the anchor into existence by
/// permanently revoking the counter-reset authority (and slot-0 re-keying) per [`SLOT0_BIRTH_DENY`].
/// After this, the counter's one-way monotonicity is a HARDWARE birth invariant, not a provisioning
/// assumption: `H0` was written exactly once (by [`init_counter_max`]) and can never be re-`init`ed.
/// The anchor identity attests this caged surface, and the receiver re-verifies it (`i_config_read`)
/// in its own chip-authenticated session — an un-caged slot 0 means "not born" ⇒ not enrolled.
///
/// ORDER: this runs **LAST** in device setup — AFTER [`init_counter_max`] (which needs slot-0
/// `mcounter_init`). i-config is boot-latched, so it reboots to latch the cage, then verifies the
/// sealed surface. Returns the now-immutable `H0`. IRREVERSIBLE — run only under the setup gate.
pub fn birth_cage_slot0<C: SpiRelayChannel>(channel: C) -> Result<u32, ProvisionError> {
    let chip = Tropic01::new(RemoteSpiDevice::new(channel));
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

    // Precondition: the counter must already hold its lifetime budget — birth seals it forever.
    let h0 = s0
        .mcounter_get(MCounterIndex::Index0)
        .map_err(|e| ProvisionError::Precondition(format!("mcounter unreadable: {e:?}")))?;

    // Precondition: slot 0 must still be factory-open on every register we are about to revoke, or the
    // chip was already (partially) caged — refuse to burn on an ambiguous surface.
    let mask = sh_mask_for(0);
    for (addr, name) in SLOT0_BIRTH_DENY {
        let r = s0.r_config_read(U16::new(*addr));
        let i = s0.i_config_read(U16::new(*addr));
        match (r, i) {
            (Ok(r), Ok(i)) if r & mask == mask && i & mask == mask => {}
            (r, i) => {
                return Err(ProvisionError::Precondition(format!(
                    "0x{addr:03x} {name}: slot-0 access not factory-open (r={r:?} i={i:?}); refusing birth burn"
                )))
            }
        }
    }

    // Burn: revoke SH0's access to each register across all 4 lanes (I_CONFIG_WRITE last, by order).
    for (addr, _name) in SLOT0_BIRTH_DENY {
        for lane in SH_LANES {
            // SH0's access bit in each lane is the lane base (session bit 0).
            s0.i_config_write(U16::new(*addr), lane).map_err(|e| {
                ProvisionError::Chip(format!("i_config_write(0x{addr:03x} bit {lane}): {e:?}"))
            })?;
        }
    }

    // Boot-latch the cage, then reopen slot 0.
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

    // Verify the sealed surface as slot 0: MCOUNTER_GET still ok (the appliance reads/decrements);
    // MCOUNTER_INIT / PAIRING_KEY_WRITE / I_CONFIG_WRITE denied (reset + re-key + un-cage are gone).
    // pairing_key_write re-writes the SAME PROD0 key, so a (failed-cage) success is idempotent.
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
        .map_err(|(_, e)| ProvisionError::CageVerify(format!("slot-0 re-open: {e:?}")))?;
    let get = s0.mcounter_get(MCounterIndex::Index0);
    let init = s0.mcounter_init(MCounterIndex::Index0, MCOUNTER_MAX);
    let pkw = s0.pairing_key_write(U16::new(0), &SH0PUB_PROD0);
    let icw = s0.i_config_write(U16::new(0x040), 0);
    let _ = s0.session_abort();

    if !is_unauthorized(&init) {
        log::warn!(
            "[provisioner] birth-cage: mcounter_init denial used a non-Unauthorized code (still denied)"
        );
    }
    let pass = get.is_ok() && init.is_err() && pkw.is_err() && icw.is_err();
    if !pass {
        return Err(ProvisionError::CageVerify(format!(
            "birth-cage surface wrong: get={get:?} init={init:?} pkw={pkw:?} icw={icw:?}"
        )));
    }
    Ok(h0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_mask_matches_the_session_bit_per_lane() {
        // Session bit N within each lane byte (SH0=bit0..SH3=bit3), 4 lanes at 0/8/16/24.
        assert_eq!(sh_mask_for(0), 0x0101_0101, "SH0 = bits {{0,8,16,24}}");
        assert_eq!(sh_mask_for(1), 0x0202_0202, "SH1 = bits {{1,9,17,25}}");
        assert_eq!(sh_mask_for(3), 0x0808_0808, "SH3 = bits {{3,11,19,27}}");
    }

    #[test]
    fn mcounter_max_is_the_hardware_ceiling() {
        // The device budget = the TROPIC01 down-counter ceiling (tropic01 MCOUNTER_VALUE_MAX).
        assert_eq!(MCOUNTER_MAX, 0xFFFF_FFFE);
        assert!(MCOUNTER_MAX > 1000);
    }
}
