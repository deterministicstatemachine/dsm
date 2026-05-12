//! §5.4 Modal Synchronization Lock: a per-relationship flag that prevents
//! concurrent online and offline transfers for the same (A, B) pair.
//!
//! The Per-Device SMT is owned by `DeviceState.smt` inside the canonical
//! `StateMachine` — there is no shadow SMT and no process-wide singleton.
//! This module keeps only the modal-sync bookkeeping; all SMT mutation and
//! inclusion-proof generation happens through `CoreSDK::execute_on_relationship`.

use std::collections::HashSet;
use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::sync::RwLock;

/// §5.4 Modal lock: set of relationship SMT keys with pending online projections.
static PENDING_ONLINE: OnceCell<Arc<RwLock<HashSet<[u8; 32]>>>> = OnceCell::new();

fn pending_online_set() -> Arc<RwLock<HashSet<[u8; 32]>>> {
    PENDING_ONLINE
        .get_or_init(|| Arc::new(RwLock::new(HashSet::new())))
        .clone()
}

/// Mark relationship `smt_key` as having a pending online projection.
/// Returns `false` if the relationship was already pending (no-op).
pub async fn set_pending_online(smt_key: &[u8; 32]) -> bool {
    let set = pending_online_set();
    let mut guard = set.write().await;
    guard.insert(*smt_key)
}

/// Clear pending-online for relationship `smt_key`.
pub async fn clear_pending_online(smt_key: &[u8; 32]) {
    let set = pending_online_set();
    let mut guard = set.write().await;
    guard.remove(smt_key);
}

/// Check if relationship `smt_key` has a pending online projection.
/// If `true`, offline (BLE) transfers for this (A,B) pair MUST be rejected
/// per §5.4 Theorem 1.
pub async fn is_pending_online(smt_key: &[u8; 32]) -> bool {
    let set = pending_online_set();
    let guard = set.read().await;
    guard.contains(smt_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_online_set_insert_and_check() {
        let key = [0xAA; 32];
        clear_pending_online(&key).await;

        assert!(!is_pending_online(&key).await);
        let inserted = set_pending_online(&key).await;
        assert!(inserted, "first insert should return true");
        assert!(is_pending_online(&key).await);
    }

    #[tokio::test]
    async fn pending_online_duplicate_insert_returns_false() {
        let key = [0xBB; 32];
        clear_pending_online(&key).await;

        set_pending_online(&key).await;
        let second = set_pending_online(&key).await;
        assert!(!second, "duplicate insert should return false");
    }

    #[tokio::test]
    async fn pending_online_clear_removes_key() {
        let key = [0xCC; 32];
        set_pending_online(&key).await;
        assert!(is_pending_online(&key).await);

        clear_pending_online(&key).await;
        assert!(!is_pending_online(&key).await);
    }

    #[tokio::test]
    async fn pending_online_independent_keys() {
        let k1 = [0x01; 32];
        let k2 = [0x02; 32];
        clear_pending_online(&k1).await;
        clear_pending_online(&k2).await;

        set_pending_online(&k1).await;
        assert!(is_pending_online(&k1).await);
        assert!(!is_pending_online(&k2).await);
    }

    #[tokio::test]
    async fn pending_online_clear_nonexistent_is_noop() {
        let key = [0xDD; 32];
        clear_pending_online(&key).await;
        clear_pending_online(&key).await;
        assert!(!is_pending_online(&key).await);
    }
}
