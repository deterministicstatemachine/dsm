//! # Bilateral Transaction Preview (Android JNI)
//!
//! Provides preview / dry-run computation for bilateral transfers before
//! the user confirms. Calculates post-transfer balances, fees, and
//! conservation checks without modifying on-chain state.

#![cfg(all(target_os = "android", feature = "jni"))]
#![allow(dead_code)]
#![allow(clippy::new_without_default)]

use std::sync::Arc;

use crate::jni::unified_protobuf_bridge::{register_post_state_predictor, PostStatePredictor};

/// Minimal deterministic predictor; extend with real logic as needed.
/// Returns Vec<u8> (not Option) to satisfy the bridge trait.
struct SdkEffectsPredictor;

impl SdkEffectsPredictor {
    pub fn new() -> Self {
        SdkEffectsPredictor
    }
}

impl PostStatePredictor for SdkEffectsPredictor {
    fn predict(&self, _pre: &[u8], _program_id: &str, _method: &str, _args: &[u8]) -> Vec<u8> {
        // Deterministic no-op prediction for now.
        Vec::new()
    }
}

/// Install the predictor into the bridge; returns true on success.
pub fn install() -> bool {
    let p: Arc<dyn PostStatePredictor> = Arc::new(SdkEffectsPredictor::new());
    register_post_state_predictor(p)
}
