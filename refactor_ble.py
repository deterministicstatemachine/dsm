
import sys, re

f_path = "dsm_client/deterministic_state_machine/dsm_sdk/src/bluetooth/bilateral_ble_handler.rs"
with open(f_path, "r") as f:
    orig = f.read()

# I will append the helper functions to `impl BilateralBleHandler {`

helpers = """
    pub async fn transition_session_to_failed(&self, commitment_hash: &[u8; 32]) {
        let pending_key = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(mut session) = sessions.remove(commitment_hash) {
                session.phase = BilateralPhase::Failed;
                session.local_commitment_hash.unwrap_or(*commitment_hash)
            } else {
                *commitment_hash
            }
        };
        let _ = crate::storage::client_db::delete_bilateral_session(commitment_hash);
        let mut mgr = self.bilateral_tx_manager.write().await;
        let _ = mgr.remove_pending_commitment(&pending_key);
    }
    
    pub async fn transition_session_to_rejected(&self, commitment_hash: &[u8; 32]) {
        self.transition_session_to_failed(commitment_hash).await;
    }

    pub async fn transition_session_to_committed(&self, commitment_hash: &[u8; 32]) {
        let pending_key = {
            let mut sessions = self.sessions.sessions.lock().await;
            if let Some(mut session) = sessions.remove(commitment_hash) {
                session.phase = BilateralPhase::Committed;
                session.local_commitment_hash.unwrap_or(*commitment_hash)
            } else {
                *commitment_hash
            }
        };
        let _ = crate::storage::client_db::delete_bilateral_session(commitment_hash);
        let mut mgr = self.bilateral_tx_manager.write().await;
        let _ = mgr.remove_pending_commitment(&pending_key);
    }
"""

if "transition_session_to_failed" not in orig:
    orig = orig.replace("impl BilateralBleHandler {", "impl BilateralBleHandler {" + helpers)

with open(f_path, "w") as f:
    f.write(orig)

