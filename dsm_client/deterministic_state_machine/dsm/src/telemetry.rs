//! Structured telemetry and logging for DSM (clockless, deterministic)
//!
//! This module provides production-grade observability with structured logging,
//! metrics collection, and tracing — without wall clocks, UUIDs, hex, JSON, or base64.
//! All IDs are deterministic counters; durations are measured in deterministic ticks from
//! `utils::deterministic_time` (not std::time).
//!
//! Constraints enforced:
//! - No wall-clock time types from std::time
//! - No uuid/base64/serde/json/hex
//! - Deterministic, event-driven counters only

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

// Deterministic tick source (event-driven), not wall clock.
use crate::utils::deterministic_time;

/// Telemetry configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for log correlation
    pub service_name: String,
    /// Environment (development, staging, production)
    pub environment: String,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable structured logging
    pub enable_structured_logging: bool,
    /// Log level (e.g., "info", "debug", "trace")
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "dsm".to_string(),
            environment: "development".to_string(),
            enable_metrics: true,
            enable_structured_logging: true,
            log_level: "info".to_string(),
        }
    }
}

/// Global telemetry state (clockless)
pub struct TelemetryState {
    _config: TelemetryConfig,
    active_requests: Arc<RwLock<HashMap<u64, RequestMetrics>>>,
    seq: AtomicU64, // deterministic request index
}

#[derive(Debug, Clone)]
struct RequestMetrics {
    start_tick: u64,    // deterministic tick when started
    _operation: String, // label only
    // Optional opaque user tag (no encoding assumptions)
    _user_tag: Option<[u8; 32]>,
}

/// Initialize telemetry (no wall clock, no UUID)
pub fn init_telemetry(config: TelemetryConfig) -> Arc<TelemetryState> {
    if config.enable_structured_logging {
        // Keep subscriber setup; this is purely output formatting, not time-based logic.
        tracing_subscriber::fmt()
            .with_env_filter(&config.log_level)
            .with_target(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .init();
    }

    info!(
        service = %config.service_name,
        environment = %config.environment,
        "Telemetry initialized (clockless)"
    );

    Arc::new(TelemetryState {
        _config: config,
        active_requests: Arc::new(RwLock::new(HashMap::new())),
        seq: AtomicU64::new(1),
    })
}

/// Structured logging macros (unchanged call sites, deterministic underneath)
pub mod log {
    /// Log a successful operation
    #[macro_export]
    macro_rules! log_success {
        ($operation:expr, $($field:tt)*) => {
            tracing::info!(
                operation = $operation,
                status = "success",
                $($field)*
            );
        };
    }

    /// Log an operation failure
    #[macro_export]
    macro_rules! log_failure {
        ($operation:expr, $error:expr, $($field:tt)*) => {
            tracing::error!(
                operation = $operation,
                status = "failure",
                error = %$error,
                $($field)*
            );
        };
    }

    /// Log a warning
    #[macro_export]
    macro_rules! log_warning {
        ($operation:expr, $message:expr, $($field:tt)*) => {
            tracing::warn!(
                operation = $operation,
                message = $message,
                $($field)*
            );
        };
    }

    /// Log an informational message
    #[macro_export]
    macro_rules! log_info {
        ($operation:expr, $($field:tt)*) => {
            tracing::info!(
                operation = $operation,
                $($field)*
            );
        };
    }

    /// Log a debug message
    #[macro_export]
    macro_rules! log_debug {
        ($operation:expr, $($field:tt)*) => {
            tracing::debug!(
                operation = $operation,
                $($field)*
            );
        };
    }
}

/// Metrics collection (purely counters/histograms/gauges keyed by deterministic values)
pub mod telemetry_metrics {
    use super::*;

    /// Record a counter metric (labels are plain &str pairs)
    pub fn increment_counter(name: &str, labels: &[(&str, &str)]) {
        let label_str = labels
            .iter()
            .map(|(k, v)| {
                // Avoid hex/base64/json; just k=v concatenation.
                let mut s = String::with_capacity(k.len() + 1 + v.len());
                s.push_str(k);
                s.push('=');
                s.push_str(v);
                s
            })
            .collect::<Vec<_>>()
            .join(", ");
        trace!(
            metric_type = "counter",
            metric_name = name,
            labels = %label_str,
            value = 1,
            "metric"
        );
    }

    /// Record a histogram metric (value is dimensionless or "ticks" where applicable)
    pub fn record_histogram(name: &str, value: u64, labels: &[(&str, &str)]) {
        let label_str = labels
            .iter()
            .map(|(k, v)| {
                let mut s = String::with_capacity(k.len() + 1 + v.len());
                s.push_str(k);
                s.push('=');
                s.push_str(v);
                s
            })
            .collect::<Vec<_>>()
            .join(", ");
        debug!(
            metric_type = "histogram",
            metric_name = name,
            labels = %label_str,
            value = value,
            "metric"
        );
    }

    /// Set a gauge metric
    pub fn set_gauge(name: &str, value: u64, labels: &[(&str, &str)]) {
        let label_str = labels
            .iter()
            .map(|(k, v)| {
                let mut s = String::with_capacity(k.len() + 1 + v.len());
                s.push_str(k);
                s.push('=');
                s.push_str(v);
                s
            })
            .collect::<Vec<_>>()
            .join(", ");
        debug!(
            metric_type = "gauge",
            metric_name = name,
            labels = %label_str,
            value = value,
            "metric"
        );
    }

    /// Record operation "duration" in deterministic ticks
    pub fn record_operation_ticks(operation: &str, ticks: u64, success: bool) {
        let status = if success { "success" } else { "failure" };
        record_histogram(
            "operation_duration_ticks",
            ticks,
            &[("operation", operation), ("status", status)],
        );
    }

    /// Record request count
    pub fn record_request(operation: &str, status: &str) {
        increment_counter(
            "requests_total",
            &[("operation", operation), ("status", status)],
        );
    }

    /// Record error count
    pub fn record_error(operation: &str, error_type: &str) {
        increment_counter(
            "errors_total",
            &[("operation", operation), ("error_type", error_type)],
        );
    }
}

/// Request tracing utilities (deterministic, no UUIDs)
pub mod trace_scope {
    use super::*;

    /// Start tracing a request. If `request_index` is None, a deterministic index is allocated.
    pub async fn start_request(
        state: &Arc<TelemetryState>,
        operation: &str,
        request_index: Option<u64>,
        user_tag: Option<[u8; 32]>,
    ) -> TraceHandle {
        let rid = match request_index {
            Some(idx) => idx,
            None => state.seq.fetch_add(1, Ordering::Relaxed),
        };

        // Deterministic "tick" snapshot
        let (_, current_tick) = deterministic_time::peek();

        {
            let mut active = state.active_requests.write().await;
            active.insert(
                rid,
                RequestMetrics {
                    start_tick: current_tick,
                    _operation: operation.to_string(),
                    _user_tag: user_tag,
                },
            );
        }

        super::telemetry_metrics::increment_counter(
            "requests_started",
            &[("operation", operation)],
        );
        TraceHandle {
            request_index: rid,
            operation: operation.to_string(),
            state: Arc::clone(state),
        }
    }

    /// Handle for tracking request lifecycle (deterministic)
    pub struct TraceHandle {
        request_index: u64,
        operation: String,
        state: Arc<TelemetryState>,
    }

    impl TraceHandle {
        /// Complete the request successfully
        #[allow(clippy::unused_async)]
        pub async fn success(self) {
            self.complete(true).await;
        }

        /// Complete the request with failure
        #[allow(clippy::unused_async)]
        pub async fn failure(self) {
            self.complete(false).await;
        }

        #[allow(clippy::unused_async)]
        async fn complete(self, success: bool) {
            let ticks_elapsed = {
                let mut active = self.state.active_requests.write().await;
                if let Some(metrics) = active.remove(&self.request_index) {
                    // Current deterministic tick
                    let (_, now_tick) = deterministic_time::peek();
                    // Saturating, clockless difference in ticks
                    now_tick.saturating_sub(metrics.start_tick)
                } else {
                    0
                }
            };

            let status = if success { "success" } else { "failure" };

            super::telemetry_metrics::record_operation_ticks(
                &self.operation,
                ticks_elapsed,
                success,
            );
            super::telemetry_metrics::record_request(&self.operation, status);

            if !success {
                super::telemetry_metrics::record_error(&self.operation, "request_failed");
            }

            // Log without hex/base64: we use the numeric request index only.
            tracing::info!(
                operation = %self.operation,
                request_index = self.request_index,
                ticks = ticks_elapsed,
                status = %status,
                "request_complete"
            );
        }
    }
}

/// Health check utilities (deterministic, no clocks)
pub mod health {
    use super::*;

    /// Record health check result
    pub fn record_health_check(component: &str, healthy: bool) {
        let status = if healthy { "healthy" } else { "unhealthy" };
        super::telemetry_metrics::set_gauge(
            "health_status",
            if healthy { 1 } else { 0 },
            &[("component", component)],
        );

        if healthy {
            debug!(operation = "health_check", component = %component, status = %status);
        } else {
            warn!(operation = "health_check", component = %component, status = %status);
        }
    }

    /// Record component startup
    pub fn record_startup(component: &str) {
        super::telemetry_metrics::increment_counter(
            "component_starts",
            &[("component", component)],
        );
        info!(operation = "component_startup", component = %component);
    }

    /// Record component shutdown
    pub fn record_shutdown(component: &str) {
        super::telemetry_metrics::increment_counter("component_stops", &[("component", component)]);
        info!(operation = "component_shutdown", component = %component);
    }
}

/// Security event logging (deterministic tags only)
pub mod security {
    use super::*;

    /// Log authentication attempt — `user_label` is a human label, not an encoded ID.
    pub fn log_auth_attempt(user_label: &str, success: bool, method: &str) {
        let status = if success { "success" } else { "failure" };
        if success {
            info!(operation = "auth_attempt", user = %user_label, method = %method, status = %status);
        } else {
            warn!(operation = "auth_attempt", user = %user_label, method = %method, status = %status);
        }
        super::telemetry_metrics::increment_counter(
            "auth_attempts",
            &[("method", method), ("status", status)],
        );
    }

    /// Log authorization decision
    pub fn log_auth_decision(user_label: &str, resource: &str, action: &str, allowed: bool) {
        let decision = if allowed { "allowed" } else { "denied" };
        if allowed {
            debug!(operation = "auth_decision", user = %user_label, resource = %resource, action = %action, decision = %decision);
        } else {
            warn!(operation = "auth_decision", user = %user_label, resource = %resource, action = %action, decision = %decision);
        }
        super::telemetry_metrics::increment_counter(
            "auth_decisions",
            &[
                ("resource", resource),
                ("action", action),
                ("decision", decision),
            ],
        );
    }

    /// Log cryptographic operation
    pub fn log_crypto_operation(operation: &str, algorithm: &str, success: bool) {
        let status = if success { "success" } else { "failure" };
        if success {
            debug!(operation = "crypto_operation", op = %operation, algorithm = %algorithm, status = %status);
        } else {
            crate::log_failure!(
                "crypto_operation",
                "cryptographic operation failed",
                op = operation,
                algorithm = algorithm,
                status = status
            );
        }
        super::telemetry_metrics::increment_counter(
            "crypto_operations",
            &[
                ("operation", operation),
                ("algorithm", algorithm),
                ("status", status),
            ],
        );
    }
}

/// Performance monitoring (ticks, no ms)
pub mod performance {
    use super::*;

    /// Record a storage operation (thresholds are in ticks; pick policy-appropriate values)
    pub fn record_db_operation(operation: &str, table: &str, ticks: u64, success: bool) {
        let status = if success { "success" } else { "failure" };
        super::telemetry_metrics::record_histogram(
            "db_operation_ticks",
            ticks,
            &[
                ("operation", operation),
                ("table", table),
                ("status", status),
            ],
        );

        // Optional "slow op" tripwire in ticks — policy-driven, not wall clock.
        if ticks > 1000 {
            warn!(operation = "slow_db_operation", op = %operation, table = %table, ticks = ticks);
        }
    }

    /// Record network operation (ticks)
    pub fn record_network_operation(operation: &str, endpoint: &str, ticks: u64, success: bool) {
        let status = if success { "success" } else { "failure" };
        super::telemetry_metrics::record_histogram(
            "network_operation_ticks",
            ticks,
            &[
                ("operation", operation),
                ("endpoint", endpoint),
                ("status", status),
            ],
        );
    }

    /// Record memory usage (bytes)
    pub fn record_memory_usage(component: &str, bytes_used: u64) {
        super::telemetry_metrics::set_gauge(
            "memory_usage_bytes",
            bytes_used,
            &[("component", component)],
        );
    }
}

/// Return a compact diagnostics snapshot as newline-delimited `key=value` bytes.
///
/// Format is plain text (`key=value\n` lines) — no JSON, no hex, no base64 —
/// so CI gate `no_clock_and_no_json.sh` is satisfied.  Callers in the SDK
/// layer may append additional fields (e.g. `db_bytes`) before forwarding.
pub fn get_global_metrics_snapshot() -> Vec<u8> {
    let (_chain_digest, tick) = deterministic_time::peek();
    format!(
        "dsm_metrics_v1\ntick={tick}\nsdk_version={}\n",
        env!("CARGO_PKG_VERSION")
    )
    .into_bytes()
}
