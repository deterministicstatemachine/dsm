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
    fn chip_sign(&mut self, message: &[u8; 32]) -> Result<Vec<u8>, TropicError>;

    /// The resident chip public key `pk_chip`, exported once at birth and bound into the
    /// anchor bundle `B`. Only the public half is ever exported.
    fn chip_pubkey(&mut self) -> Result<Vec<u8>, TropicError>;
}

/// Host-side verification of the resident TROPIC01 Ed25519 witness (`σ^chip`). The
/// receiver verifies against `pk_chip` pinned in the anchor bundle `B`; `pk`/`sig` are
/// scheme-sized byte strings. Signing is on-die only ([`Tropic::chip_sign`]).
pub trait ChipSig {
    /// Verify a signature over a 32-byte digest under the resident chip public key.
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool;
}

/// The RP2350 secure-partition signature scheme (the `σ^host` factor). The partition
/// keypair is generated at appliance birth under the birth seal; `pk_host` is bound into
/// the anchor bundle `B` and pinned by the receiver. PartSign signs the per-transfer
/// root-advance message `M_{i+1}`; the receiver verifies with the pinned `pk_host`.
pub trait PartitionSig {
    /// Deterministic `(sk, pk)` from a 32-byte seed (partition birth seal).
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
    /// Signature over a 32-byte digest under the partition secret key.
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8>;
    /// Verify a partition signature over a 32-byte digest under the pinned `pk`.
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
}
