// SPDX-License-Identifier: MIT OR Apache-2.0
//! Install adapters that project the SDK's async app router into the
//! synchronous core bridge so queries driven from JNI/WebView can succeed.
//!
//! - Protobuf-only, bytes-only. The adapter never parses or re-encodes payloads.
//! - Returns whatever the SDK router produced (e.g., ResultPack { codec=PROTO, body=... }).
//! - Strict-fail if the SDK router is not available; no alternate paths.

use std::sync::Arc;
use std::panic::{catch_unwind, AssertUnwindSafe};

use once_cell::sync::OnceCell;
use tokio::runtime::Handle;

use crate::bridge as sdk_bridge;

/// Adapter that dynamically fetches the current SDK app router on each call.
/// This allows the underlying SDK router to be replaced (e.g., MinimalBootstrapRouter → AppRouterImpl)
/// without reinstalling the core adapter.
struct CoreAppRouterAdapter {
    handle: Handle,
}

impl CoreAppRouterAdapter {
    fn new(handle: Handle) -> Self {
        Self { handle }
    }
}

impl dsm::core::bridge::AppRouter for CoreAppRouterAdapter {
    fn handle_query(&self, path: &str, params_proto: &[u8]) -> Result<Vec<u8>, String> {
        log::info!(
            "[CORE_APP_ROUTER_ADAPTER] handle_query path={} params_len={} thread={:?}",
            path,
            params_proto.len(),
            std::thread::current().id()
        );

        // Fetch the current SDK router dynamically (supports hot-swap from bootstrap to full router)
        let router =
            sdk_bridge::app_router().ok_or_else(|| "SDK app router not installed".to_string())?;

        let path = path.to_string();
        let params = params_proto.to_vec();
        let handle = self.handle.clone();

        // Ensure no panic crosses the bridge.
        catch_unwind(AssertUnwindSafe(move || {
            handle.block_on(async move {
                let result = router.query(sdk_bridge::AppQuery { path, params }).await;
                log::info!(
                    "[CORE_APP_ROUTER_ADAPTER] query result success={} error={:?} data_len={}",
                    result.success,
                    result.error_message,
                    result.data.len()
                );
                if result.success {
                    Ok(result.data)
                } else {
                    Err(result
                        .error_message
                        .unwrap_or_else(|| "App router query failed".to_string()))
                }
            })
        }))
        .map_err(|_| "App router query panicked".to_string())?
    }

    fn handle_invoke(&self, method: &str, args_proto: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        // Fetch the current SDK router dynamically (supports hot-swap from bootstrap to full router)
        let router =
            sdk_bridge::app_router().ok_or_else(|| "SDK app router not installed".to_string())?;

        let method = method.to_string();
        let args = args_proto.to_vec();
        let handle = self.handle.clone();

        // Ensure no panic crosses the bridge.
        catch_unwind(AssertUnwindSafe(move || {
            handle.block_on(async move {
                let result = router.invoke(sdk_bridge::AppInvoke { method, args }).await;
                if result.success {
                    // Second Vec<u8> slot reserved for future sideband bytes; keep empty for now.
                    Ok((result.data, Vec::new()))
                } else {
                    Err(result
                        .error_message
                        .unwrap_or_else(|| "App router invoke failed".to_string()))
                }
            })
        }))
        .map_err(|_| "App router invoke panicked".to_string())?
    }
}

static CORE_APP_ROUTER_INSTALLED: OnceCell<()> = OnceCell::new();

/// Install the adapter exactly once. If already installed, the call is a no-op.
/// The adapter dynamically fetches the current SDK router on each call, so the SDK router
/// can be replaced after installation (e.g., MinimalBootstrapRouter → AppRouterImpl).
pub fn install_app_router_adapter(handle: Handle) {
    // Fast path: already installed
    if CORE_APP_ROUTER_INSTALLED.get().is_some() {
        log::debug!("Core app router adapter already installed, skipping");
        return;
    }

    log::info!("Installing core app router adapter (dynamic SDK router fetch)");
    let adapter = CoreAppRouterAdapter::new(handle);
    if let Err(e) = dsm::core::bridge::install_app_router(Arc::new(adapter)) {
        log::error!("Failed to install core app router adapter: {:?}", e);
        return;
    }
    let _ = CORE_APP_ROUTER_INSTALLED.set(());
    log::info!("Core app router adapter installed successfully");
}

/// Check if the app router adapter has been installed.
pub fn is_app_router_installed() -> bool {
    CORE_APP_ROUTER_INSTALLED.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_app_router_adapter_constructs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let adapter = CoreAppRouterAdapter::new(rt.handle().clone());
        let _ = adapter.handle;
    }

    #[test]
    #[ignore = "flaky under parallel execution: depends on global APP_ROUTER state"]
    fn handle_query_fails_without_sdk_router() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let adapter = CoreAppRouterAdapter::new(rt.handle().clone());
        let result = dsm::core::bridge::AppRouter::handle_query(&adapter, "/test", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not installed"));
    }

    #[test]
    #[ignore = "flaky under parallel execution: depends on global APP_ROUTER state"]
    fn handle_invoke_fails_without_sdk_router() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let adapter = CoreAppRouterAdapter::new(rt.handle().clone());
        let result = dsm::core::bridge::AppRouter::handle_invoke(&adapter, "test_method", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not installed"));
    }

    #[test]
    #[ignore = "flaky under parallel execution: depends on global APP_ROUTER state"]
    fn handle_query_with_empty_path() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let adapter = CoreAppRouterAdapter::new(rt.handle().clone());
        let result = dsm::core::bridge::AppRouter::handle_query(&adapter, "", &[]);
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "flaky under parallel execution: depends on global APP_ROUTER state"]
    fn handle_invoke_with_large_payload() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let adapter = CoreAppRouterAdapter::new(rt.handle().clone());
        let big_payload = vec![0xFFu8; 1024 * 1024];
        let result =
            dsm::core::bridge::AppRouter::handle_invoke(&adapter, "big_method", &big_payload);
        assert!(result.is_err());
    }
}
