// SPDX-License-Identifier: MIT OR Apache-2.0

//! §5.4 Modal Synchronization Lock: a per-relationship flag that prevents
//! concurrent online and offline transfers for the same (A, B) pair.
//!
//! The Per-Device SMT is owned by `DeviceState.smt` inside the canonical
//! `StateMachine` — there is no shadow SMT and no process-wide singleton.
//! This module keeps only the modal-sync bookkeeping; all SMT mutation and
//! inclusion-proof generation happens through `CoreSDK::execute_on_relationship`.

use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;

/// §5.4 Modal lock: set of relationship SMT keys with pending online projections.
static PENDING_ONLINE: OnceCell<Arc<RwLock<HashSet<[u8; 32]>>>> = OnceCell::new();

fn pending_online_set() -> Arc<RwLock<HashSet<[u8; 32]>>> {
    PENDING_ONLINE
        .get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
        .clone()
}

/// Mark relationship `smt_key` as having a pending online projection.
/// Returns `false` if the relationship was already pending (no-op).
///
/// Prefer [`PendingOnlineGuard::acquire`] — a bare `set` obliges every exit path
/// to remember to clear, which is how the flag leaks.
pub fn set_pending_online(smt_key: &[u8; 32]) -> bool {
    pending_online_set().write().insert(*smt_key)
}

/// Clear pending-online for relationship `smt_key`.
pub fn clear_pending_online(smt_key: &[u8; 32]) {
    pending_online_set().write().remove(smt_key);
}

/// RAII holder for the modal lock.
///
/// This flag is APPLICATION state, not protocol state. Protocol rollback is
/// provided by the advance transaction; this is not, and it does not get
/// unwound by a database rollback. It therefore has to be released on EVERY
/// exit — the success path, each early error return, and any panic.
///
/// Doing that by hand is how it leaks: the submission-uncertain return, for
/// instance, exited before ever reaching the manual clear, wedging that
/// relationship for the rest of the process lifetime. A guard cannot be
/// forgotten, and cannot be deleted by accident alongside the protocol
/// rollbacks it sits next to.
#[must_use = "dropping the guard immediately releases the modal lock"]
pub struct PendingOnlineGuard {
    smt_key: [u8; 32],
}

impl PendingOnlineGuard {
    /// Take the modal lock for a relationship.
    ///
    /// Returns `None` when the relationship is ALREADY pending — the caller
    /// must fail closed rather than start a second concurrent transfer.
    pub fn acquire(smt_key: &[u8; 32]) -> Option<Self> {
        if set_pending_online(smt_key) {
            Some(Self { smt_key: *smt_key })
        } else {
            None
        }
    }

    /// The relationship this guard holds.
    pub fn smt_key(&self) -> &[u8; 32] {
        &self.smt_key
    }
}

impl Drop for PendingOnlineGuard {
    fn drop(&mut self) {
        clear_pending_online(&self.smt_key);
    }
}

/// Check if relationship `smt_key` has a pending online projection.
/// If `true`, offline (BLE) transfers for this (A,B) pair MUST be rejected
/// per §5.4 Theorem 1.
pub fn is_pending_online(smt_key: &[u8; 32]) -> bool {
    let set = pending_online_set();
    let guard = set.read();
    guard.contains(smt_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_online_set_insert_and_check() {
        let key = [0xAA; 32];
        clear_pending_online(&key);

        assert!(!is_pending_online(&key));
        let inserted = set_pending_online(&key);
        assert!(inserted, "first insert should return true");
        assert!(is_pending_online(&key));
    }

    #[test]
    fn pending_online_duplicate_insert_returns_false() {
        let key = [0xBB; 32];
        clear_pending_online(&key);

        set_pending_online(&key);
        let second = set_pending_online(&key);
        assert!(!second, "duplicate insert should return false");
    }

    #[test]
    fn pending_online_clear_removes_key() {
        let key = [0xCC; 32];
        set_pending_online(&key);
        assert!(is_pending_online(&key));

        clear_pending_online(&key);
        assert!(!is_pending_online(&key));
    }

    #[test]
    fn pending_online_independent_keys() {
        let k1 = [0x01; 32];
        let k2 = [0x02; 32];
        clear_pending_online(&k1);
        clear_pending_online(&k2);

        set_pending_online(&k1);
        assert!(is_pending_online(&k1));
        assert!(!is_pending_online(&k2));
    }

    #[test]
    fn pending_online_clear_nonexistent_is_noop() {
        let key = [0xDD; 32];
        clear_pending_online(&key);
        clear_pending_online(&key);
        assert!(!is_pending_online(&key));
    }

    /// The guard must release on EVERY exit — including the early-return paths
    /// that previously skipped the hand-written clear and wedged the
    /// relationship for the rest of the process lifetime.
    #[test]
    fn guard_releases_on_early_return() {
        let key = [0xA7u8; 32];
        clear_pending_online(&key);

        fn send_that_fails_early(key: &[u8; 32]) -> Result<(), &'static str> {
            let _lock = PendingOnlineGuard::acquire(key).ok_or("already pending")?;
            // The submission-uncertain shape: bail out well before any
            // hand-written cleanup would have run.
            Err("submission uncertain")
        }

        assert!(send_that_fails_early(&key).is_err());
        assert!(
            !is_pending_online(&key),
            "the modal lock MUST be released even when the send returns early"
        );
    }

    /// A second concurrent transfer on the same relationship must fail closed
    /// while the first still holds the lock, and succeed once it is dropped.
    #[test]
    fn guard_excludes_a_concurrent_transfer_then_frees_it() {
        let key = [0xB4u8; 32];
        clear_pending_online(&key);

        let first = PendingOnlineGuard::acquire(&key).expect("first acquires");
        assert!(
            PendingOnlineGuard::acquire(&key).is_none(),
            "a second concurrent online transfer must fail closed"
        );
        assert!(is_pending_online(&key));

        drop(first);
        assert!(!is_pending_online(&key));
        assert!(
            PendingOnlineGuard::acquire(&key).is_some(),
            "the relationship is usable again once the first transfer finishes"
        );
    }

    /// A panic must not strand the flag either.
    #[test]
    fn guard_releases_on_panic() {
        let key = [0xC9u8; 32];
        clear_pending_online(&key);

        let outcome = std::panic::catch_unwind(|| {
            let _lock = PendingOnlineGuard::acquire(&key).expect("acquires");
            panic!("mid-send failure");
        });

        assert!(outcome.is_err());
        assert!(
            !is_pending_online(&key),
            "a panic must not wedge the relationship"
        );
    }
}
