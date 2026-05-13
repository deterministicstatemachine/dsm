// dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bootstrap_adapter.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! BootstrapHandler adapter shim.
//!
//! The canonical genesis implementation is `handlers::system_routes::handle_system_genesis_query`
//! on the ingress/router path. This adapter remains only for ABI compatibility with the core
//! bridge bootstrap hook and intentionally rejects execution.

use std::sync::Arc;

use dsm::types::proto as generated;

struct CoreBootstrapAdapter;

impl CoreBootstrapAdapter {
    fn new() -> Self {
        Self
    }

    fn derive_request_cdbrw_binding(
        req: &generated::SystemGenesisRequest,
    ) -> Result<[u8; 32], String> {
        if req.cdbrw_hw_entropy.is_empty() {
            return Err("system.genesis: cdbrw_hw_entropy is required".to_string());
        }
        if req.cdbrw_env_fingerprint.is_empty() {
            return Err("system.genesis: cdbrw_env_fingerprint is required".to_string());
        }
        if req.cdbrw_salt.len() != 32 {
            return Err(format!(
                "system.genesis: cdbrw_salt must be 32 bytes, got {}",
                req.cdbrw_salt.len()
            ));
        }

        dsm::crypto::cdbrw_binding::derive_cdbrw_binding_key(
            &req.cdbrw_hw_entropy,
            &req.cdbrw_env_fingerprint,
            &req.cdbrw_salt,
        )
        .map_err(|e| format!("system.genesis: C-DBRW binding derivation failed: {e}"))
    }

    fn run_system_genesis(req: generated::SystemGenesisRequest) -> Result<Vec<u8>, String> {
        if req.device_entropy.len() != 32 {
            return Err("system.genesis: device_entropy must be 32 bytes".to_string());
        }
        let _ = Self::derive_request_cdbrw_binding(&req)?;
        Err(
            "bootstrap adapter genesis path removed; use canonical ingress route system.genesis"
                .to_string(),
        )
    }
}

impl dsm::core::BootstrapHandler for CoreBootstrapAdapter {
    fn handle_system_genesis(
        &self,
        req: generated::SystemGenesisRequest,
    ) -> Result<Vec<u8>, String> {
        Self::run_system_genesis(req)
    }
}

/// Idempotent installation exposed to JNI/init layer.
///
/// Kept for ABI stability; this adapter intentionally refuses direct genesis handling.
pub fn install_bootstrap_adapter() {
    use dsm::core::install_bootstrap_handler;
    install_bootstrap_handler(Arc::new(CoreBootstrapAdapter::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_cdbrw(
        hw: Vec<u8>,
        env: Vec<u8>,
        salt: Vec<u8>,
    ) -> generated::SystemGenesisRequest {
        generated::SystemGenesisRequest {
            locale: "en-US".to_string(),
            network_id: "testnet".to_string(),
            device_entropy: vec![0x42; 32],
            cdbrw_hw_entropy: hw,
            cdbrw_env_fingerprint: env,
            cdbrw_salt: salt,
        }
    }

    #[test]
    fn derive_binding_rejects_missing_hw_entropy() {
        let req = request_with_cdbrw(Vec::new(), vec![1], vec![0; 32]);
        let err = CoreBootstrapAdapter::derive_request_cdbrw_binding(&req)
            .expect_err("expected missing hw entropy error");
        assert!(err.contains("cdbrw_hw_entropy"));
    }

    #[test]
    fn derive_binding_rejects_missing_env_fingerprint() {
        let req = request_with_cdbrw(vec![1], Vec::new(), vec![0; 32]);
        let err = CoreBootstrapAdapter::derive_request_cdbrw_binding(&req)
            .expect_err("expected missing env fingerprint error");
        assert!(err.contains("cdbrw_env_fingerprint"));
    }

    #[test]
    fn derive_binding_rejects_invalid_salt_length() {
        let req = request_with_cdbrw(vec![1], vec![2], vec![0; 31]);
        let err = CoreBootstrapAdapter::derive_request_cdbrw_binding(&req)
            .expect_err("expected invalid salt length error");
        assert!(err.contains("cdbrw_salt must be 32 bytes"));
    }

    #[test]
    fn run_system_genesis_is_disabled() {
        let req = request_with_cdbrw(vec![1], vec![2], vec![3; 32]);
        let err = CoreBootstrapAdapter::run_system_genesis(req)
            .expect_err("expected disabled path error");
        assert!(err.contains("removed"));
    }
}
