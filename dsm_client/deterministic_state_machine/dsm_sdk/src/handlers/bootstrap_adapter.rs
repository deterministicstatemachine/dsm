// dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bootstrap_adapter.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core bridge BootstrapHandler adapter implemented in the SDK.
//!
//! Provides the `system.genesis` entrypoint exposed to the JNI/init layer.
//!
//! Genesis MPC creation is intrinsically online and storage-node-coupled
//! (WP §10, §14; storage-node spec): the ceremony requires N≥3 distinct
//! storage nodes that each contribute a reveal in a two-phase commit/reveal
//! handshake against real storage-node endpoints. Until a real
//! `SdkGenesisMpcTransport` is wired into this adapter, `system.genesis`
//! refuses to mint a fake genesis rather than produce one with no real
//! participants.

use std::sync::Arc;

use dsm::types::proto as generated;

struct CoreBootstrapAdapter;

impl CoreBootstrapAdapter {
    fn new() -> Self {
        CoreBootstrapAdapter
    }

    fn run_system_genesis(req: generated::SystemGenesisRequest) -> Result<Vec<u8>, String> {
        // Validate entropy strictly so callers learn about wire-format errors
        // before they discover the missing transport.
        if req.device_entropy.len() != 32 {
            return Err("system.genesis: device_entropy must be 32 bytes".to_string());
        }

        Err(
            "system.genesis: SdkGenesisMpcTransport not wired; genesis MPC requires \
             interaction with ≥3 distinct storage nodes (WP §10/§14). The bootstrap \
             adapter must be initialized with a transport that performs the two-phase \
             commit/reveal handshake against real storage-node endpoints."
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

/// Idempotent installation exposed to JNI/init layer
pub fn install_bootstrap_adapter() {
    use dsm::core::install_bootstrap_handler;
    install_bootstrap_handler(Arc::new(CoreBootstrapAdapter::new()));
}
