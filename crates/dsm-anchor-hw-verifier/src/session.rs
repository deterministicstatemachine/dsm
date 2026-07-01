// SPDX-License-Identifier: MIT OR Apache-2.0
//! The receiver-operated Path-B counter verifier session.
//!
//! The receiver (Phone B) opens its OWN authenticated libtropic-rs session to the SENDER's
//! TROPIC01 (chip A), over a [`RemoteSpiDevice`], and reads the physical monotonic down-counter `H`
//! itself. Nothing the sender says about the counter is trusted; the value comes back inside B's
//! end-to-end AES-256-GCM session, which the relay cannot forge or read.
//!
//! Every failure — transport error, chip-info error, identity mismatch, session-handshake failure,
//! counter-read failure, or a malformed response — returns `Err`, which the acceptance predicate
//! treats as FAIL-CLOSED (the offline-bearer transfer recovers online). A counter is trusted only
//! when the whole path succeeds against the pinned chip.

use dsm_anchor_verifier::{RemoteSpiDevice, SpiRelayChannel};
use tropic01::{MCounterIndex, Tropic01, X25519Dalek};
use x25519_dalek::{PublicKey, StaticSecret};

/// What the receiver holds to open its authenticated verifier session to a specific enrolled chip.
///
/// `sh_priv` is B's OWN pairing secret (persisted in B's key store, for the dedicated verifier
/// pairing slot on A's chip). `pinned_static_pubkey` is A's chip Noise static public key, pinned at
/// enrollment: it guards against the relay being pointed at a DIFFERENT chip (anti-substitution).
#[derive(Clone)]
pub struct VerifierSessionCredential {
    /// The pairing slot index on A's TROPIC01 that B's pairing key is enrolled into (the read-only
    /// "verifier pairing slot"). If A never provisioned it, `session_start` fails -> fail-closed.
    pub slot: u8,
    /// B's pairing PUBLIC key (enrolled in `slot` on A's chip).
    pub sh_pub: [u8; 32],
    /// B's pairing PRIVATE key (B's secret). Authenticates B to the chip in the handshake.
    pub sh_priv: [u8; 32],
    /// A's chip Noise static PUBLIC key (`stpub`), pinned at enrollment. B compares the chip's
    /// presented static key against this BEFORE trusting any counter, so a relay to an
    /// attacker-substituted chip is rejected.
    pub pinned_static_pubkey: [u8; 32],
}

/// Why a Path-B counter read failed. Every variant is fail-closed at the acceptance predicate.
#[derive(Debug, Clone)]
pub enum VerifierError {
    /// Reading the chip's certificate/identity over the relay failed (transport or parse).
    ChipInfo(String),
    /// The chip's presented Noise static key does not match the pinned `stpub`. The relay reached
    /// a DIFFERENT chip than the enrolled one — reject.
    IdentityMismatch,
    /// The authenticated L3 handshake failed: wrong/absent verifier slot, bad pairing key, or a
    /// forged/MITM relay. No session -> no counter.
    SessionStart(String),
    /// `MCounter_Get` over the established session failed or returned a malformed response.
    CounterRead(String),
}

impl core::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifierError::ChipInfo(w) => write!(f, "chip-info read failed: {w}"),
            VerifierError::IdentityMismatch => {
                write!(
                    f,
                    "chip identity mismatch (relay reached the wrong TROPIC01)"
                )
            }
            VerifierError::SessionStart(w) => write!(f, "verifier session handshake failed: {w}"),
            VerifierError::CounterRead(w) => write!(f, "authenticated counter read failed: {w}"),
        }
    }
}

impl std::error::Error for VerifierError {}

/// Open a verifier session to chip A over `channel` and return its live physical counter `H`
/// (`H_attested`). `ephemeral_secret` is a fresh 32-byte CSPRNG scalar the caller supplies (the
/// SDK feeds it from DSM's CSPRNG) — one per session, for handshake forward secrecy.
///
/// Order (all fail-closed): pin the chip identity, open the authenticated session with B's pairing
/// credential, read the counter. On `Ok(h)`, the caller checks `h == H0 - (u_i + 1)`.
pub fn read_live_counter<C: SpiRelayChannel>(
    channel: C,
    cred: &VerifierSessionCredential,
    ephemeral_secret: [u8; 32],
) -> Result<u32, VerifierError> {
    let mut chip = Tropic01::new(RemoteSpiDevice::new(channel));

    // (1) Anti-substitution: pin the chip's Noise static key BEFORE trusting anything it says.
    // Copy the 32 bytes out so the borrow of `chip` ends before `session_start` consumes it.
    let stpub: [u8; 32] = {
        let cert = chip
            .get_info_cert_store()
            .map_err(|e| VerifierError::ChipInfo(format!("{e:?}")))?;
        *cert
            .public_key()
            .map_err(|e| VerifierError::ChipInfo(format!("cert public key: {e:?}")))?
    };
    if stpub != cred.pinned_static_pubkey {
        return Err(VerifierError::IdentityMismatch);
    }

    // (2) Open the authenticated L3 session with B's verifier pairing credential.
    let ehpriv = StaticSecret::from(ephemeral_secret);
    let ehpub = PublicKey::from(&ehpriv);
    let shpub = PublicKey::from(cred.sh_pub);
    let shpriv = StaticSecret::from(cred.sh_priv);
    let mut session = chip
        .session_start(&X25519Dalek, shpub, shpriv, ehpub, ehpriv, cred.slot)
        .map_err(|(_, e)| VerifierError::SessionStart(format!("{e:?}")))?;

    // (3) Read the live physical counter H over the encrypted session.
    let h = session
        .mcounter_get(MCounterIndex::Index0)
        .map_err(|e| VerifierError::CounterRead(format!("{e:?}")))?;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm_anchor_verifier::RelayError;

    fn cred() -> VerifierSessionCredential {
        VerifierSessionCredential {
            slot: 1,
            sh_pub: [0x11; 32],
            sh_priv: [0x22; 32],
            pinned_static_pubkey: [0x33; 32],
        }
    }

    /// A relay whose transport is down: the very first chip-info transaction fails, so the whole
    /// read fails CLOSED (no session, no counter).
    struct DeadChannel;
    impl SpiRelayChannel for DeadChannel {
        fn transceive(&mut self, _mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
            Err(RelayError::Transport("relay down".into()))
        }
    }

    #[test]
    fn transport_down_fails_closed_at_chip_info() {
        let r = read_live_counter(DeadChannel, &cred(), [7u8; 32]);
        assert!(matches!(r, Err(VerifierError::ChipInfo(_))), "got {r:?}");
    }

    /// A relay that returns plausible-length-but-garbage bytes: chip-info parsing fails, still
    /// fail-closed (never reaches a counter).
    struct GarbageChannel;
    impl SpiRelayChannel for GarbageChannel {
        fn transceive(&mut self, mosi: &[u8]) -> Result<Vec<u8>, RelayError> {
            Ok(vec![0xABu8; mosi.len()])
        }
    }

    #[test]
    fn garbage_chip_info_fails_closed() {
        let r = read_live_counter(GarbageChannel, &cred(), [7u8; 32]);
        assert!(
            r.is_err(),
            "garbage chip must not yield a trusted counter: {r:?}"
        );
    }
}
