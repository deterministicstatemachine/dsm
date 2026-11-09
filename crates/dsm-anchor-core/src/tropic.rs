//! The TROPIC01 secure-element abstraction the v2 witness flow needs, plus the two
//! pluggable signature schemes the appliance profile fixes:
//!   - [`ChipSig`] — verification of the resident non-exportable Ed25519 key inside
//!     TROPIC01 (the `σ^chip` factor). Signing happens on the die via
//!     [`Tropic::chip_sign`]; the key never leaves the chip. Its at-rest protection is
//!     the die's physically unclonable function.
//!   - [`PartitionSig`] — the RP2350 secure-partition signature scheme (the `σ^host`
//!     factor), under a key generated at birth and sealed to the partition.
//!
//! Keeping these as traits lets the protocol core stay hardware- and scheme-agnostic and
//! unit-test on the host with deterministic mocks; the firmware wires the real libtropic
//! `ECC_Key` / `EdDSA` (chip) and `MCounter` (the counter, now a non-rewind floor), and
//! the chosen partition signature scheme.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TropicError {
    /// SPI / L3-session failure, or chip absent.
    Comm,
    /// `MCounter_Update` on an exhausted counter (`H == 0`) — online only.
    CounterExhausted,
    /// The chip took the command and refused it: a key or slot in the wrong state, an access the
    /// session's pairing slot is denied, a command or parameter it does not accept.
    Refused,
    /// After closing its birth the chip still accepts a command the closed birth denies.
    CageOpen,
    /// The board's random generator failed its own health tests: nothing random is drawn from it.
    NoEntropy,
}

/// TROPIC01 primitives used over an authenticated L3 session, mediated by the RP2350
/// secure partition. The non-secure partition/host cannot invoke these. The counter is a
/// non-rewind floor + offline exposure cap (not an acceptance authority); `chip_sign` is
/// the resident-key possession witness `σ^chip`.
pub trait Tropic {
    /// Live monotonic down-counter value `H` (§8); `u = H₀ − H`.
    fn counter_get(&mut self) -> Result<u32, TropicError>;

    /// `MCounter_Update`: `H ← H − 1`. Returns [`TropicError::CounterExhausted`] if `H == 0`.
    fn counter_update(&mut self) -> Result<(), TropicError>;

    /// `σ^chip = ChipSign(M_{i+1})` — the resident non-exportable Ed25519 key inside
    /// TROPIC01 signs the 32-byte root-advance message. The private half never leaves the die.
    ///
    /// The public half `pk_chip` is read once at enrollment (bound into the anchor bundle `B`)
    /// via the chip's own key-read primitive, not through this trait.
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError>;

    /// Whether `signature` is the resident key's over `message`, under its public half `pk_chip`.
    /// The chip hedges its Ed25519 signatures, so two over one message differ: a signature is checked
    /// by verifying it, never by signing again and comparing.
    fn chip_signature_holds(&self, pk_chip: &[u8], message: &[u8; 32], signature: &[u8]) -> bool;

    /// Close the chip to a second birth: the pairing slot the appliance runs on may no longer
    /// re-initialize the counter, write or invalidate pairing keys, or write the chip's access
    /// configuration, and the closed configuration is in force when this returns. A chip already
    /// closed is closed. Irreversible on silicon.
    fn close_birth(&mut self) -> Result<(), TropicError>;

    /// Set the counter back to its start after a try-run's spend moved it. The chip takes this only
    /// before its birth is closed, and a power cut before it is undone by the next boot.
    fn set_counter_back(&mut self) -> Result<(), TropicError>;

    /// Go through what closing the birth needs with its permanent parts substituted, reporting each
    /// step ([`crate::try_run`]). Leaves the chip as it found it: what is written is undone, and what
    /// cannot be undone is not written but checked to be what the chip would take.
    fn rehearse_birth(&mut self) -> Vec<crate::try_run::TryStep>;

    /// Fresh randomness for a receive challenge, from both hardware sources: 32 bytes from the
    /// board's own generator, passed by its health tests, and 32 from the chip's (`Random_Value_Get`).
    fn challenge_entropy(&mut self) -> Result<ChallengeEntropy, TropicError>;
}

/// Randomness for one receive challenge, from each hardware source.
pub struct ChallengeEntropy {
    pub board: [u8; 32],
    pub chip: [u8; 32],
}

impl Drop for ChallengeEntropy {
    fn drop(&mut self) {
        crate::util::zeroize(&mut self.board);
        crate::util::zeroize(&mut self.chip);
    }
}

/// A chip lent for a while, as a try-run borrows it.
impl<T: Tropic + ?Sized> Tropic for &mut T {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        (**self).counter_get()
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        (**self).counter_update()
    }
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        (**self).chip_sign(message)
    }
    fn chip_signature_holds(&self, pk_chip: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        (**self).chip_signature_holds(pk_chip, message, signature)
    }
    fn close_birth(&mut self) -> Result<(), TropicError> {
        (**self).close_birth()
    }
    fn set_counter_back(&mut self) -> Result<(), TropicError> {
        (**self).set_counter_back()
    }
    fn rehearse_birth(&mut self) -> Vec<crate::try_run::TryStep> {
        (**self).rehearse_birth()
    }
    fn challenge_entropy(&mut self) -> Result<ChallengeEntropy, TropicError> {
        (**self).challenge_entropy()
    }
}

/// Forward `Tropic` through a `Box`, so a firmware holding the appliance in a `'static` slot can
/// erase the (unnameable) concrete chip-session type behind `Box<dyn Tropic>` and still satisfy
/// `Appliance<T: Tropic, P>`. The RP2350 secure monitor needs this: its SG handler is reached by a
/// hardware `bxns` (not a call it can pass state into), so the appliance must live in a static of a
/// nameable type. Signing/counter behavior is unchanged — the box is a pointer indirection only.
impl<T: Tropic + ?Sized> Tropic for alloc::boxed::Box<T> {
    fn counter_get(&mut self) -> Result<u32, TropicError> {
        (**self).counter_get()
    }
    fn counter_update(&mut self) -> Result<(), TropicError> {
        (**self).counter_update()
    }
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError> {
        (**self).chip_sign(message)
    }
    fn chip_signature_holds(&self, pk_chip: &[u8], message: &[u8; 32], signature: &[u8]) -> bool {
        (**self).chip_signature_holds(pk_chip, message, signature)
    }
    fn close_birth(&mut self) -> Result<(), TropicError> {
        (**self).close_birth()
    }
    fn set_counter_back(&mut self) -> Result<(), TropicError> {
        (**self).set_counter_back()
    }
    fn rehearse_birth(&mut self) -> Vec<crate::try_run::TryStep> {
        (**self).rehearse_birth()
    }
    fn challenge_entropy(&mut self) -> Result<ChallengeEntropy, TropicError> {
        (**self).challenge_entropy()
    }
}

/// Host-side verification of the resident TROPIC01 Ed25519 witness (`σ^chip`). The
/// receiver verifies against `pk_chip` pinned in the anchor bundle `B`; `pk`/`sig` are
/// scheme-sized byte strings. Signing is on-die only ([`Tropic::chip_sign`]).
pub trait ChipSig {
    /// Verify a signature over a 32-byte digest under the resident chip public key.
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool;
}

/// Why the partition could not generate its keypair or sign. No `σ^host` exists then, and none
/// is put in its place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PartitionError {
    /// The scheme refused the secret key it was given.
    SecretKey,
    /// The scheme refused the message it was given.
    Message,
    /// The signer's own verification of the signature it made failed.
    SelfCheck,
}

/// The RP2350 secure-partition signature scheme (the `σ^host` factor). The partition
/// keypair is generated at appliance birth under the birth seal; `pk_host` is bound into
/// the anchor bundle `B` and pinned by the receiver. PartSign signs the per-transfer
/// root-advance message `M_{i+1}`; the receiver verifies with the pinned `pk_host`.
pub trait PartitionSig {
    /// Deterministic `(sk, pk)` from a 32-byte seed (partition birth seal).
    fn part_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError>;
    /// Signature over a 32-byte digest under the partition secret key.
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError>;
    /// Verify a partition signature over a 32-byte digest under the pinned `pk`.
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
    /// Verify the owner's authorization of a prepare: a signature over the
    /// [`crate::appliance::owner_authorization_digest`] under the device key `pk_on` the anchor
    /// was provisioned for (DSM's device key scheme, BLAKE3-SPHINCS+ SPX256f).
    fn owner_verify(pk_on: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
    /// A device key in the owner's scheme from a 32-byte seed, `(sk, pk)`: the try-run's rehearsal
    /// owner, so its payment goes through the same authorization a real one does. A key the anchor
    /// derives for itself is never the key it was provisioned for, so it authorizes nothing real.
    fn owner_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError>;
    /// A signature in the owner's scheme over a 32-byte digest: the rehearsal owner's
    /// authorization of the try-run's own payment.
    fn owner_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError>;
}

/// Verification of the partition witness `σ^host` alone: what a receiver or a walker of an
/// offline account needs, which never generates a partition key or signs. Every
/// [`PartitionSig`] verifies.
pub trait HostSig {
    /// Verify a partition signature over a 32-byte digest under the pinned `pk_host`.
    fn verify(pk_host: &[u8], message: &[u8; 32], sig: &[u8]) -> bool;
}

impl<P: PartitionSig> HostSig for P {
    fn verify(pk_host: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        P::part_verify(pk_host, message, sig)
    }
}
