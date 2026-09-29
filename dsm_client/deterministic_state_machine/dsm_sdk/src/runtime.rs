// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Tokio Runtime Singleton
//!
//! Provides a process-wide multi-threaded Tokio runtime for the SDK,
//! initialized lazily on first use by [`get_runtime`]. The runtime is never
//! reset during the process lifetime to preserve production safety
//! invariants.

use once_cell::sync::OnceCell;
use log::{error, info};
use tokio::runtime::{Builder, Runtime};

pub(crate) static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn build_runtime_or_abort() -> Runtime {
    match Builder::new_multi_thread()
        .enable_all()
        .thread_name("dsm-sdk-runtime")
        .build()
    {
        Ok(rt) => {
            info!("[dsm_sdk] Tokio runtime initialized");
            rt
        }
        Err(e) => {
            error!("[dsm_sdk] CRITICAL: failed to build Tokio runtime: {e}");
            std::process::abort();
        }
    }
}

pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(build_runtime_or_abort)
}

// NOTE: reset_runtime_for_tests intentionally removed.
// Production safety invariants forbid arbitrary runtime resets.
