// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed C-DBRW access gate.
//!
//! All sensitive router operations consult this gate before running. If the
//! trust state has never been established, or has decayed below the required
//! minimum, the gate rejects the call. There is no observe-only path and no
//! default-allow fallback — every call on an un-enrolled device blocks.
//!
//! ## Clockless
//!
//! The gate carries a monotonic [`TRUST_ITER`] counter derived from
//! `AtomicU64::fetch_add`. It does **not** read wall-clock time. Callers use
//! the iter value purely for logical "update happened at tick N" ordering.
//! This is consistent with the protocol rule banning wall-clock markers in
//! semantics (see `.github/instructions/rules.instructions.md`).
//!
//! ## Fail-closed ordering
//!
//! [`AccessLevel`] variants are numerically ascending by trust:
//! `Blocked < ReadOnly < PinRequired < FullAccess`. A call to
//! [`require_access_level`] with minimum `m` passes iff `current >= m`.
//!
//! ## Single source of truth
//!
//! `cdbrw_responder`, `cdbrw_enrollment_writer`, and the measure-trust
//! route all publish into [`store_trust`]. Read paths call [`latest_trust`]
//! or go straight to [`require_access_level`]. Nothing else may write to
//! the gate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use dsm::types::proto as generated;

/// Fail-closed access verdict returned by the gate.
///
/// Ordering is ascending-by-trust so `<` / `>=` on ordinals give the
/// intuitive predicate (`current >= required`). Values match the numeric
/// ordinals of the [`generated::CdbrwAccessLevel`] protobuf enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AccessLevel {
    /// No verdict has ever been published, or the last verdict was fatal.
    /// Every gated operation fails.
    Blocked = 1,
    /// Degraded entropy (health test FAIL). View-only; no writes, no sends,
    /// no bilateral commits.
    ReadOnly = 2,
    /// Drift or ADAPTED resonance. Writes allowed once the UI runs a step-up
    /// auth prompt. From the gate's perspective this is `>= ReadOnly`, so
    /// read-only gates pass.
    PinRequired = 3,
    /// PASS or RESONANT classification with clean W1 drift.
    FullAccess = 4,
}

impl AccessLevel {
    /// Convert a protobuf enum value (as `i32`) into an [`AccessLevel`].
    /// Unknown / unspecified values become [`AccessLevel::Blocked`] (fail-closed).
    pub fn from_proto_i32(value: i32) -> Self {
        match generated::CdbrwAccessLevel::try_from(value) {
            Ok(generated::CdbrwAccessLevel::CdbrwAccessFullAccess) => AccessLevel::FullAccess,
            Ok(generated::CdbrwAccessLevel::CdbrwAccessPinRequired) => AccessLevel::PinRequired,
            Ok(generated::CdbrwAccessLevel::CdbrwAccessReadOnly) => AccessLevel::ReadOnly,
            Ok(generated::CdbrwAccessLevel::CdbrwAccessBlocked)
            | Ok(generated::CdbrwAccessLevel::CdbrwAccessUnspecified)
            | Err(_) => AccessLevel::Blocked,
        }
    }

    /// Convert to the protobuf enum variant.
    pub fn to_proto(self) -> generated::CdbrwAccessLevel {
        match self {
            AccessLevel::FullAccess => generated::CdbrwAccessLevel::CdbrwAccessFullAccess,
            AccessLevel::PinRequired => generated::CdbrwAccessLevel::CdbrwAccessPinRequired,
            AccessLevel::ReadOnly => generated::CdbrwAccessLevel::CdbrwAccessReadOnly,
            AccessLevel::Blocked => generated::CdbrwAccessLevel::CdbrwAccessBlocked,
        }
    }

    /// Convert to protobuf enum discriminant (`i32`).
    pub fn to_proto_i32(self) -> i32 {
        self.to_proto() as i32
    }

    /// Human-readable name for diagnostics (no secrets, no localized text).
    pub fn as_str(self) -> &'static str {
        match self {
            AccessLevel::Blocked => "BLOCKED",
            AccessLevel::ReadOnly => "READ_ONLY",
            AccessLevel::PinRequired => "PIN_REQUIRED",
            AccessLevel::FullAccess => "FULL_ACCESS",
        }
    }
}

/// Tri-layer resonant classification (C-DBRW §7). Mirrors the proto enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResonantStatus {
    /// No classification has been published yet.
    Unspecified,
    /// All three §4.5.7 conditions met.
    Pass,
    /// ρ exceeds raw threshold but h₀_eff ≥ h_min (Theorem 8.1(ii)).
    Resonant,
    /// h₀_eff below h_min but ≥ adapted floor (Remark 4.6); longer orbit req'd.
    Adapted,
    /// Fundamental entropy collapse — Ĥ or L̂ below threshold.
    Fail,
}

impl ResonantStatus {
    pub fn to_proto(self) -> generated::CdbrwResonantStatus {
        match self {
            ResonantStatus::Pass => generated::CdbrwResonantStatus::CdbrwResonantPass,
            ResonantStatus::Resonant => generated::CdbrwResonantStatus::CdbrwResonantResonant,
            ResonantStatus::Adapted => generated::CdbrwResonantStatus::CdbrwResonantAdapted,
            ResonantStatus::Fail => generated::CdbrwResonantStatus::CdbrwResonantFail,
            ResonantStatus::Unspecified => {
                generated::CdbrwResonantStatus::CdbrwResonantUnspecified
            }
        }
    }

    pub fn to_proto_i32(self) -> i32 {
        self.to_proto() as i32
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ResonantStatus::Pass => "PASS",
            ResonantStatus::Resonant => "RESONANT",
            ResonantStatus::Adapted => "ADAPTED",
            ResonantStatus::Fail => "FAIL",
            ResonantStatus::Unspecified => "NOT_RUN",
        }
    }
}

/// Diagnostic trust-state snapshot published by the responder / enrollment
/// writer / measure-trust route.
///
/// `iter` is a clockless monotonic tick (see [`TRUST_ITER`]). Every field
/// except `access_level` and `resonant_status` is diagnostic — authorization
/// decisions must go through [`require_access_level`] and rely on
/// `access_level` alone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrustSnapshot {
    pub access_level: AccessLevel,
    pub resonant_status: ResonantStatus,
    pub h_hat: f32,
    pub rho_hat: f32,
    pub l_hat: f32,
    pub h0_eff: f32,
    pub trust_score: f32,
    pub recommended_n: u32,
    pub w1_distance: f32,
    pub w1_threshold: f32,
    pub iter: u64,
}

impl TrustSnapshot {
    /// Convert into the flat proto mirror used by all C-DBRW responses.
    pub fn to_proto(&self, note: impl Into<String>) -> generated::CdbrwTrustSnapshot {
        generated::CdbrwTrustSnapshot {
            access_level: self.access_level.to_proto_i32(),
            resonant_status: self.resonant_status.to_proto_i32(),
            h_hat: self.h_hat,
            rho_hat: self.rho_hat,
            l_hat: self.l_hat,
            h0_eff: self.h0_eff,
            trust_score: self.trust_score,
            iter: self.iter,
            recommended_n: self.recommended_n,
            w1_distance: self.w1_distance,
            w1_threshold: self.w1_threshold,
            note: note.into(),
        }
    }

    /// A neutral "nothing has been computed yet" snapshot. Access is
    /// [`AccessLevel::Blocked`] so the gate fails closed on a fresh process.
    pub const fn blocked_default() -> Self {
        Self {
            access_level: AccessLevel::Blocked,
            resonant_status: ResonantStatus::Unspecified,
            h_hat: 0.0,
            rho_hat: 0.0,
            l_hat: 0.0,
            h0_eff: 0.0,
            trust_score: 0.0,
            recommended_n: 0,
            w1_distance: 0.0,
            w1_threshold: 0.0,
            iter: 0,
        }
    }
}

/// Monotonic "trust update tick" counter. Clockless per
/// `.github/instructions/rules.instructions.md`. Each call to
/// [`next_iter`] returns a strictly increasing `u64`.
pub static TRUST_ITER: AtomicU64 = AtomicU64::new(0);

/// Reserve and return the next iter value. Used as the canonical "how
/// recently was this snapshot produced?" ordering.
pub fn next_iter() -> u64 {
    TRUST_ITER.fetch_add(1, Ordering::AcqRel).wrapping_add(1)
}

static LAST_TRUST: RwLock<Option<TrustSnapshot>> = RwLock::new(None);

/// Publish a new trust snapshot. Called by `cdbrw_responder`, the enrollment
/// writer, and the measure-trust route. Never called directly by handlers.
///
/// If the `iter` field is 0, the caller forgot to reserve an iter via
/// [`next_iter`] — the gate still accepts it but logs a warning.
pub fn store_trust(snapshot: TrustSnapshot) {
    if snapshot.iter == 0 {
        log::warn!(
            "[cdbrw_access_gate] store_trust called with iter=0 — caller should use next_iter()"
        );
    }
    log::info!(
        "[cdbrw_access_gate] store_trust iter={} access={} resonant={} h_hat={:.4} rho_hat={:.4} l_hat={:.4} h0_eff={:.4} w1={:.6}/{:.6} trust_score={:.3}",
        snapshot.iter,
        snapshot.access_level.as_str(),
        snapshot.resonant_status.as_str(),
        snapshot.h_hat,
        snapshot.rho_hat,
        snapshot.l_hat,
        snapshot.h0_eff,
        snapshot.w1_distance,
        snapshot.w1_threshold,
        snapshot.trust_score,
    );
    match LAST_TRUST.write() {
        Ok(mut guard) => *guard = Some(snapshot),
        Err(e) => {
            // Poisoned lock indicates a previous panic during update. Recover
            // by taking the guard and overwriting — failing closed is never
            // appropriate for a publish op because the old snapshot is known
            // stale at this point.
            log::error!(
                "[cdbrw_access_gate] LAST_TRUST lock poisoned during store_trust: {e} — recovering"
            );
            let mut guard = e.into_inner();
            *guard = Some(snapshot);
        }
    }
}

/// Read the last published trust snapshot. Returns `None` when no C-DBRW
/// computation has ever produced a verdict in this process.
pub fn latest_trust() -> Option<TrustSnapshot> {
    match LAST_TRUST.read() {
        Ok(guard) => *guard,
        Err(e) => {
            log::error!(
                "[cdbrw_access_gate] LAST_TRUST lock poisoned during read: {e} — treating as Blocked"
            );
            None
        }
    }
}

/// Clear the published snapshot. Only used by tests and by the shutdown path
/// to guarantee that a restart begins fail-closed.
pub fn clear_trust_for_test() {
    match LAST_TRUST.write() {
        Ok(mut guard) => *guard = None,
        Err(e) => {
            let mut guard = e.into_inner();
            *guard = None;
        }
    }
}

/// Shared test mutex guarding access-gate state.
///
/// `LAST_TRUST` and `TRUST_ITER` are process-global, so any two tests that
/// call [`store_trust`] / [`next_iter`] race on the same state. Module-local
/// mutexes are not enough because cargo runs tests from different modules in
/// parallel by default. Every test that touches the gate must acquire this
/// mutex for the full duration of the test body (including reads performed
/// after the update), so no concurrent test can stomp on `LAST_TRUST` between
/// `store_trust` and `latest_trust`.
#[cfg(test)]
pub(crate) fn gate_test_mutex() -> &'static std::sync::Mutex<()> {
    static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    GUARD.get_or_init(|| std::sync::Mutex::new(()))
}

/// Fail-closed authorization predicate.
///
/// Passes when a trust snapshot has been published *and* its `access_level`
/// is numerically `>= minimum`. Returns a diagnostic error message describing
/// the observed state when it rejects — the caller is expected to surface the
/// error via the `err()` response helper rather than inventing its own reason.
///
/// # Examples (conceptual)
///
/// - Wallet send requires [`AccessLevel::PinRequired`]. A `Blocked` or
///   `ReadOnly` state rejects; a `PinRequired` or `FullAccess` state passes
///   (the PIN UI is a frontend concern and is not enforced by this gate).
/// - Contact list read requires [`AccessLevel::ReadOnly`]. A `Blocked` state
///   rejects; anything ≥ `ReadOnly` passes.
/// - Bootstrap and enrollment routes DO NOT call this — they must remain
///   callable before any snapshot exists.
pub fn require_access_level(minimum: AccessLevel) -> Result<TrustSnapshot, String> {
    match latest_trust() {
        Some(snapshot) if snapshot.access_level >= minimum => Ok(snapshot),
        Some(snapshot) => Err(format!(
            "C-DBRW access denied: required {} but current={} (resonant={} iter={})",
            minimum.as_str(),
            snapshot.access_level.as_str(),
            snapshot.resonant_status.as_str(),
            snapshot.iter
        )),
        None => Err(format!(
            "C-DBRW access denied: required {} but no trust snapshot has been published",
            minimum.as_str()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_clean_state<F: FnOnce()>(f: F) {
        let guard = match gate_test_mutex().lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        clear_trust_for_test();
        f();
        clear_trust_for_test();
        drop(guard);
    }

    fn snapshot_with(level: AccessLevel, resonant: ResonantStatus) -> TrustSnapshot {
        TrustSnapshot {
            access_level: level,
            resonant_status: resonant,
            h_hat: 0.5,
            rho_hat: 0.1,
            l_hat: 0.5,
            h0_eff: 0.45,
            trust_score: 0.9,
            recommended_n: 4096,
            w1_distance: 0.01,
            w1_threshold: 0.05,
            iter: next_iter(),
        }
    }

    #[test]
    fn ordering_is_ascending_by_trust() {
        assert!(AccessLevel::Blocked < AccessLevel::ReadOnly);
        assert!(AccessLevel::ReadOnly < AccessLevel::PinRequired);
        assert!(AccessLevel::PinRequired < AccessLevel::FullAccess);
    }

    #[test]
    fn from_proto_unspecified_is_blocked() {
        assert_eq!(AccessLevel::from_proto_i32(0), AccessLevel::Blocked);
        assert_eq!(AccessLevel::from_proto_i32(-1), AccessLevel::Blocked);
        assert_eq!(AccessLevel::from_proto_i32(999), AccessLevel::Blocked);
    }

    #[test]
    fn from_proto_round_trip() {
        for lvl in [
            AccessLevel::Blocked,
            AccessLevel::ReadOnly,
            AccessLevel::PinRequired,
            AccessLevel::FullAccess,
        ] {
            assert_eq!(AccessLevel::from_proto_i32(lvl.to_proto_i32()), lvl);
        }
    }

    #[test]
    fn require_without_snapshot_rejects() {
        with_clean_state(|| {
            let result = require_access_level(AccessLevel::ReadOnly);
            assert!(result.is_err(), "fresh state must fail closed");
            let msg = result.unwrap_err();
            assert!(msg.contains("no trust snapshot"), "got: {msg}");
        });
    }

    #[test]
    fn require_below_minimum_rejects() {
        with_clean_state(|| {
            store_trust(snapshot_with(AccessLevel::ReadOnly, ResonantStatus::Fail));
            let result = require_access_level(AccessLevel::PinRequired);
            assert!(result.is_err(), "ReadOnly must not satisfy PinRequired");
        });
    }

    #[test]
    fn require_at_minimum_passes() {
        with_clean_state(|| {
            store_trust(snapshot_with(
                AccessLevel::PinRequired,
                ResonantStatus::Adapted,
            ));
            let result = require_access_level(AccessLevel::PinRequired);
            assert!(result.is_ok(), "PinRequired must satisfy PinRequired");
            assert_eq!(result.unwrap().access_level, AccessLevel::PinRequired);
        });
    }

    #[test]
    fn require_above_minimum_passes() {
        with_clean_state(|| {
            store_trust(snapshot_with(
                AccessLevel::FullAccess,
                ResonantStatus::Pass,
            ));
            let result = require_access_level(AccessLevel::ReadOnly);
            assert!(result.is_ok(), "FullAccess must satisfy ReadOnly");
        });
    }

    #[test]
    fn blocked_rejects_everything_including_read_only() {
        with_clean_state(|| {
            store_trust(snapshot_with(AccessLevel::Blocked, ResonantStatus::Fail));
            assert!(require_access_level(AccessLevel::ReadOnly).is_err());
            assert!(require_access_level(AccessLevel::PinRequired).is_err());
            assert!(require_access_level(AccessLevel::FullAccess).is_err());
        });
    }

    #[test]
    fn store_overwrites_previous() {
        with_clean_state(|| {
            store_trust(snapshot_with(AccessLevel::ReadOnly, ResonantStatus::Fail));
            store_trust(snapshot_with(
                AccessLevel::FullAccess,
                ResonantStatus::Pass,
            ));
            assert_eq!(
                latest_trust().map(|s| s.access_level),
                Some(AccessLevel::FullAccess)
            );
        });
    }

    #[test]
    fn next_iter_is_strictly_monotonic() {
        let a = next_iter();
        let b = next_iter();
        let c = next_iter();
        assert!(a < b);
        assert!(b < c);
    }
}
