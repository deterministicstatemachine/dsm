#![cfg(target_os = "android")]
//! # JNI Result Types
//!
//! Minimal result wrapper types for the JNI production bridge.
//! Android-only; gated to avoid non-Android build errors.

#[derive(Debug, Clone)]
pub struct JniResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    /// Deterministic tick (no wall clock)
    pub tick: u64,
}

impl<T> JniResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            tick: crate::util::deterministic_time::tick(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
            tick: crate::util::deterministic_time::tick(),
        }
    }
}
