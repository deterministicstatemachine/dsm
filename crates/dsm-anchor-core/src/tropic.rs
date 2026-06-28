//! The TROPIC01 secure-element abstraction the fused witness flow needs, plus the
//! two pluggable signature schemes the appliance profile fixes (§5):
//!   - [`WitnessSig`] — the TROPIC01-keyed hardware witness (StepKeyGen / StepSign
//!     / StepVerify); the profile is WOTS over BLAKE3 (`sig::WotsBlake3`).
//!   - [`PartitionSig`] — the RP2350 secure-partition signature scheme
//!     (PartKeyGen / PartSign / PartVerify) under a partition key generated at
//!     birth and bound into the anchor bundle `B`.
//!
//! Keeping all three as traits lets the protocol core stay hardware- and
//! scheme-agnostic and unit-test on the host with deterministic mocks; the
//! firmware wires the real libtropic `MAC_And_Destroy` / `MCounter` (two slots,
//! `q_boot` for boot fencing and `q_tx` for transfer witnesses) and the chosen
//! signature schemes.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TropicError {
    /// SPI / L3-session failure, or chip absent.
    Comm,
    /// The selected MACANDD slot is not in the expected armed state.
    NotArmed,
    /// `MCounter_Update` on an exhausted counter (`H == 0`) — online only.
    CounterExhausted,
}

/// TROPIC01 primitives used over an authenticated L3 session, mediated by the
/// RP2350 secure partition. The non-secure partition/host cannot invoke these.
/// Two MACANDD slots are used: `q_boot` (boot fence) and `q_tx` (transfer witness).
pub trait Tropic {
    /// `W = MACANDD(q, X)` — one call evolves slot `q`'s state and returns the
    /// 32-byte witness output (Def. 19/20). A slot must be armed first.
    fn mac_and_destroy(&mut self, q: u16, x: &[u8; 32]) -> Result<[u8; 32], TropicError>;

    /// Live monotonic down-counter value `H` (§3); `u = H₀ − H`.
    fn counter_get(&mut self) -> Result<u32, TropicError>;

    /// `MCounter_Update`: `H ← H − 1`. Returns [`TropicError::CounterExhausted`]
    /// if `H == 0`.
    fn counter_update(&mut self) -> Result<(), TropicError>;
}

/// The TROPIC01-keyed hardware-witness signature scheme (deterministic from a
/// 32-byte seed). `keygen` is StepKeyGen, `sign` is StepSign, `verify` is
/// StepVerify (§5, §19). `pk`/`sig` are scheme-sized byte strings.
pub trait WitnessSig {
    /// Deterministic `(sk, pk)` from a 32-byte seed (the witness key material Kᵀ).
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
    /// Deterministic signature over a 32-byte digest under `sk`.
    fn sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8>;
    /// Verify a signature over a 32-byte digest under `pk`.
    fn verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
}

/// The RP2350 secure-partition signature scheme (§5). The partition keypair is
/// generated at appliance birth; `pk` is bound into the anchor bundle `B` and
/// pinned by the receiver. PartSign signs the boot certificate and the per-transfer
/// partition final certificate; the receiver verifies with the pinned `pk`.
pub trait PartitionSig {
    /// Deterministic `(sk, pk)` from a 32-byte seed (partition birth entropy).
    fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);
    /// Signature over a 32-byte digest under the partition secret key.
    fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8>;
    /// Verify a partition signature over a 32-byte digest under the pinned `pk`.
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool;
}
