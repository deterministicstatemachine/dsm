//! # Tokio Runtime Singleton
//!
//! Provides a process-wide multi-threaded Tokio runtime for the SDK.
//! Initialized lazily on first use (or explicitly via the `extern "C"`
//! [`dsm_init_runtime`] entry point). The runtime is never reset during
//! the process lifetime to preserve production safety invariants.

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

#[no_mangle]
pub extern "C" fn dsm_init_runtime() {
    RUNTIME.get_or_init(build_runtime_or_abort);
}

pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(build_runtime_or_abort)
}

// NOTE: reset_runtime_for_tests intentionally removed.
// Production safety invariants forbid arbitrary runtime resets.
