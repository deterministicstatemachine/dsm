// path: dsm_client/deterministic_state_machine/dsm/src/utils/timeout.rs
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Timeout utilities for DSM operations (tick-typed; clockless by default).

use crate::types::error::DsmError;
use crate::utils::time::Duration; // Duration is tick-based, not wall-clock
use core::future::Future;
use std::sync::OnceLock;
use tracing::{debug, warn};

/// Device performance calibration data
#[derive(Debug, Clone)]
pub struct DeviceCalibration {
    /// Baseline ticks per second (measured during calibration)
    pub ticks_per_second: f64,
    /// Scaling factor relative to reference device (1.0 = reference performance)
    pub performance_factor: f64,
}

impl Default for DeviceCalibration {
    fn default() -> Self {
        // Conservative defaults for uncalibrated devices
        Self {
            ticks_per_second: 12.0, // ~12ms per tick (120 ticks/second)
            performance_factor: 1.0,
        }
    }
}

/// Global device calibration storage (initialized once during app startup)
static DEVICE_CALIBRATION: OnceLock<DeviceCalibration> = OnceLock::new();

/// Set device calibration data (called once during app initialization)
pub fn set_device_calibration(calibration: DeviceCalibration) {
    let _ = DEVICE_CALIBRATION.set(calibration);
}

/// Get device calibration data (returns default if not set)
pub fn get_device_calibration() -> &'static DeviceCalibration {
    DEVICE_CALIBRATION.get_or_init(DeviceCalibration::default)
}

/// Run device performance calibration (call during app initialization)
/// Returns the calibration data that was stored globally
pub async fn calibrate_device_performance() -> Result<&'static DeviceCalibration, String> {
    use crate::util::deterministic_time as dt;

    // Adaptive calibration:
    // Run work in batches until we have a statistically significant duration (in ticks).
    // This prevents "tick drift" on fast devices (where 2500 ops might finish in 0-1 ticks)
    // and prevents hang on slow devices (where 2500 ops might take seconds).

    let mut current_iterations = 2500; // Start with previous default
    let target_min_ticks: u64 = 20; // Require at least 20 ticks for precision
    let mut total_ticks = 0;
    let mut total_ops = 0;

    let loop_limit = 5; // Avoid infinite loops

    for _ in 0..loop_limit {
        let start_tick = dt::tick_index();

        // Perform calibration workload (simple BLAKE3 hashes)
        for i in 0..current_iterations {
            let _ = crate::crypto::blake3::domain_hash(
                "DSM/calibration",
                format!("calibration-data-{}", i).as_bytes(),
            );
        }

        let end_tick = dt::tick_index();
        let ticks = end_tick.saturating_sub(start_tick);

        total_ops += current_iterations;
        total_ticks += ticks;

        if total_ticks >= target_min_ticks {
            break;
        }

        // If we haven't accumulated enough ticks, double the work and retry
        current_iterations *= 2;
        // Cap max iterations to avoid freezing
        if current_iterations > 1_000_000 {
            break;
        }
    }

    // Calculate performance metrics
    let operations_per_tick = if total_ticks > 0 {
        total_ops as f64 / total_ticks as f64
    } else {
        // Default path for extremely fast devices that still report 0 ticks
        // This suggests tick resolution is too coarse or device is supercomputer.
        // Assume very high performance.
        1000.0
    };

    // Reference device performance (estimated baseline)
    // This represents a "typical" device performance (Pixel 5 class)
    let reference_performance = 5.0; // ops per tick baseline

    // Calculate performance factor (higher = faster device)
    let performance_factor = operations_per_tick / reference_performance;

    let calibration = DeviceCalibration {
        ticks_per_second: operations_per_tick,
        // Loosen the clamp to handle wider beta hardware variance (critique recommendation)
        performance_factor: performance_factor.clamp(0.05, 20.0),
    };

    // Warn if device is an outlier (too slow or too fast)
    // Adjusted thresholds per critique to be less discriminatory against budget phones
    if !(0.1..=15.0).contains(&performance_factor) {
        warn!(
            performance_factor,
            "Device performance outlier detected - network timing may be affected"
        );
    }

    // Store globally
    set_device_calibration(calibration);

    debug!(
        operations_per_tick = operations_per_tick,
        performance_factor = performance_factor,
        total_ticks = total_ticks,
        "Device performance calibration completed (Adaptive)"
    );

    Ok(get_device_calibration())
}

/// Operation types for retry/timeout configuration.
#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    GenesisCreation,
    IdentityVerification,
    StorageNodeConnectivity,
    MpcContribution,
    TransactionProcessing,
    BilateralTransaction,
    CryptoOperation,
    HttpRequest,
}

impl OperationType {
    pub fn timeout(&self) -> Duration {
        match self {
            Self::GenesisCreation => TimeoutConfig::genesis_creation(),
            Self::IdentityVerification => TimeoutConfig::identity_verification(),
            Self::StorageNodeConnectivity => TimeoutConfig::storage_node_connectivity(),
            Self::MpcContribution => TimeoutConfig::mpc_contribution(),
            Self::TransactionProcessing => TimeoutConfig::transaction_processing(),
            Self::BilateralTransaction => TimeoutConfig::bilateral_transaction(),
            Self::CryptoOperation => TimeoutConfig::crypto_operation(),
            Self::HttpRequest => TimeoutConfig::http_request(),
        }
    }

    pub fn retry_count(&self) -> usize {
        match self {
            Self::GenesisCreation => 1,
            Self::IdentityVerification => 3,
            Self::StorageNodeConnectivity => 3,
            Self::MpcContribution => 2,
            Self::TransactionProcessing => 3,
            Self::BilateralTransaction => 2,
            Self::CryptoOperation => 2,
            Self::HttpRequest => 3,
        }
    }

    pub fn should_retry(&self) -> bool {
        matches!(
            self,
            Self::IdentityVerification
                | Self::StorageNodeConnectivity
                | Self::TransactionProcessing
                | Self::HttpRequest
        )
    }
}

/// Typed timeouts for operations (ticks).
pub struct TimeoutConfig;

impl TimeoutConfig {
    #[inline]
    pub fn genesis_creation() -> Duration {
        Duration::from_ticks(50_000) // ~600s @ 12ms/tick
    }
    #[inline]
    pub fn identity_verification() -> Duration {
        Duration::from_ticks(2_500) // ~30s
    }
    #[inline]
    pub fn storage_node_connectivity() -> Duration {
        Duration::from_ticks(833) // ~10s
    }
    #[inline]
    pub fn mpc_contribution() -> Duration {
        Duration::from_ticks(5_000) // ~60s
    }
    #[inline]
    pub fn transaction_processing() -> Duration {
        Duration::from_ticks(2_500) // ~30s
    }
    #[inline]
    pub fn bilateral_transaction() -> Duration {
        // Dynamic timeout based on device performance calibration
        let calibration = get_device_calibration();
        let base_ticks = 10_000u64; // Base timeout for reference device

        // Scale timeout inversely with performance (slower devices get more time)
        // performance_factor < 1.0 means slower device, so increase timeout
        let scaled_ticks = if calibration.performance_factor > 0.0 {
            (base_ticks as f64 / calibration.performance_factor) as u64
        } else {
            base_ticks // Default to base if calibration is invalid
        };

        // Cap at reasonable maximum (e.g., 5x base timeout for very slow devices)
        let max_ticks = base_ticks * 5;
        let final_ticks = scaled_ticks.min(max_ticks);

        Duration::from_ticks(final_ticks)
    }
    #[inline]
    pub fn crypto_operation() -> Duration {
        Duration::from_ticks(833) // ~10s
    }
    #[inline]
    pub fn http_request() -> Duration {
        Duration::from_ticks(416) // ~5s
    }
}

// All timeout/sleep logic is tick-based and deterministic. No wall-clock time.
mod rt_time {
    use super::Duration;
    use core::future::Future;

    pub async fn with_timeout<F, T>(_dur: Duration, fut: F) -> Result<T, ()>
    where
        F: Future<Output = T>,
    {
        // Deterministic: no wall-clock timeouts, just run the future.
        Ok(fut.await)
    }

    pub async fn sleep(_dur: Duration) {
        // Deterministic: no-op.
    }
}

/// Execute an operation with a timeout (Tokio bridge is internal and feature-gated).
pub async fn with_timeout<T, F, E>(timeout_duration: Duration, operation: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: From<DsmError>,
{
    debug!(
        timeout_ticks = timeout_duration.as_ticks(),
        "Starting operation with timeout"
    );

    match rt_time::with_timeout(timeout_duration, operation).await {
        Ok(res) => res,
        Err(_) => Err(DsmError::timeout("operation timed out").into()),
    }
}

/// Execute an operation with retries (tick delays).
pub async fn with_retry_and_timeout<F, Fut, T>(
    mut operation: F,
    operation_type: OperationType,
) -> Result<T, DsmError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, DsmError>>,
{
    let retry_count = operation_type.retry_count();
    let mut last_error: Option<DsmError> = None;

    for attempt in 0..retry_count {
        debug!(
            ?operation_type,
            attempt = attempt + 1,
            total_attempts = retry_count,
            "Attempting operation"
        );

        match with_timeout::<T, _, DsmError>(operation_type.timeout(), operation()).await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        ?operation_type,
                        successful_attempt = attempt + 1,
                        "Operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                warn!(?operation_type, attempt = attempt + 1, error = %e, "Operation attempt failed");
                last_error = Some(e);

                if attempt < retry_count.saturating_sub(1) && operation_type.should_retry() {
                    let delay = calculate_retry_delay(attempt);
                    debug!(delay_ticks = delay.as_ticks(), "Waiting before retry");
                    rt_time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        DsmError::internal(
            format!("All {retry_count} attempts failed for {operation_type:?}"),
            Option::<core::convert::Infallible>::None,
        )
    }))
}

/// Exponential backoff with cap (ticks).
pub fn calculate_retry_delay(attempt: usize) -> Duration {
    let base_delay = Duration::from_ticks(2000); // ticks
    let max_delay = Duration::from_ticks(8000); // ticks
    let factor: u32 = 2_u32.pow(attempt as u32).min(4);
    (base_delay * factor).min(max_delay)
}
