// SPDX-License-Identifier: Apache-2.0
//! Operational Tooling for DSM Storage Nodes
//! Provides monitoring, health checks, metrics collection, and operational utilities.

use dsm::util::deterministic_time as dt;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Health status of a storage node
#[derive(Debug, Clone)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub component: String,
    pub status: HealthStatus,
    pub message: String,
    pub timestamp_tick: u64,
    pub duration_ticks: u64,
}

/// System metrics
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub disk_usage_bytes: u64,
    pub network_bytes_received: u64,
    pub network_bytes_sent: u64,
    pub uptime_ticks: u64,
    pub active_connections: u32,
}

/// Storage metrics
#[derive(Debug, Clone)]
pub struct StorageMetrics {
    pub total_objects: u64,
    pub total_bytes: u64,
    pub operations_per_tick: f64,
    pub average_latency_ticks: f64,
    pub error_rate: f64,
    pub partition_distribution: HashMap<String, u64>,
}

/// Operational alert
#[derive(Debug, Clone)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub component: String,
    pub message: String,
    pub timestamp_tick: u64,
    pub resolved: bool,
}

/// Alert severity levels
#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Monitoring dashboard data
#[derive(Debug, Clone)]
pub struct DashboardData {
    pub node_id: String,
    pub health_checks: Vec<HealthCheck>,
    pub system_metrics: SystemMetrics,
    pub storage_metrics: StorageMetrics,
    pub active_alerts: Vec<Alert>,
    pub recent_logs: Vec<String>,
}

/// Health checker for storage node components
type HealthCheckFuture = Pin<Box<dyn Future<Output = HealthCheck> + Send>>;
type HealthCheckFnBox = Box<dyn Fn() -> HealthCheckFuture + Send + Sync>;

pub struct HealthChecker {
    checks: HashMap<String, HealthCheckFnBox>,
}

pub trait HealthCheckFn: Send + Sync {
    fn check(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthCheck> + Send>>;
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
        }
    }

    pub fn register_check<F, Fut>(&mut self, name: String, check_fn: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HealthCheck> + Send + 'static,
    {
        self.checks
            .insert(name, Box::new(move || Box::pin(check_fn())));
    }

    pub async fn run_all_checks(&self) -> Vec<HealthCheck> {
        let mut results = Vec::new();

        for check_fn in self.checks.values() {
            let start_tick = dt::tick_index();
            let mut check_result = check_fn().await;
            let end_tick = dt::tick_index();
            check_result.duration_ticks = end_tick.saturating_sub(start_tick);
            results.push(check_result);
        }

        results
    }

    pub fn get_overall_health(&self, checks: &[HealthCheck]) -> HealthStatus {
        let mut has_warnings = false;
        let mut has_errors = false;

        for check in checks {
            match check.status {
                HealthStatus::Critical => return HealthStatus::Critical,
                HealthStatus::Unhealthy => has_errors = true,
                HealthStatus::Degraded => has_warnings = true,
                HealthStatus::Healthy => {}
            }
        }

        if has_errors {
            HealthStatus::Unhealthy
        } else if has_warnings {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics collector
pub struct MetricsCollector {
    system_metrics: Arc<RwLock<SystemMetrics>>,
    storage_metrics: Arc<RwLock<StorageMetrics>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            system_metrics: Arc::new(RwLock::new(SystemMetrics {
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                disk_usage_bytes: 0,
                network_bytes_received: 0,
                network_bytes_sent: 0,
                uptime_ticks: 0,
                active_connections: 0,
            })),
            storage_metrics: Arc::new(RwLock::new(StorageMetrics {
                total_objects: 0,
                total_bytes: 0,
                operations_per_tick: 0.0,
                average_latency_ticks: 0.0,
                error_rate: 0.0,
                partition_distribution: HashMap::new(),
            })),
        }
    }

    pub async fn update_system_metrics(&self) {
        let mut metrics = self.system_metrics.write().await;
        metrics.uptime_ticks = metrics.uptime_ticks.saturating_add(1);
    }

    pub async fn update_storage_metrics(
        &self,
        operations: u64,
        bytes: u64,
        latency_ticks: u64,
        errors: u64,
    ) {
        let mut metrics = self.storage_metrics.write().await;

        metrics.total_objects += 1;
        metrics.total_bytes += bytes;

        // Update rolling averages
        let alpha = 0.1; // Smoothing factor
        metrics.operations_per_tick =
            metrics.operations_per_tick * (1.0 - alpha) + (operations as f64) * alpha;
        metrics.average_latency_ticks =
            metrics.average_latency_ticks * (1.0 - alpha) + (latency_ticks as f64) * alpha;

        if operations > 0 {
            metrics.error_rate =
                metrics.error_rate * (1.0 - alpha) + (errors as f64 / operations as f64) * alpha;
        }
    }

    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    pub async fn get_storage_metrics(&self) -> StorageMetrics {
        self.storage_metrics.read().await.clone()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert manager
pub struct AlertManager {
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn raise_alert(&self, alert: Alert) {
        let mut alerts = self.alerts.write().await;
        alerts.insert(alert.id.clone(), alert);
    }

    pub async fn resolve_alert(&self, alert_id: &str) {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.resolved = true;
        }
    }

    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .values()
            .filter(|alert| !alert.resolved)
            .cloned()
            .collect()
    }

    pub async fn check_thresholds(
        &self,
        metrics: &SystemMetrics,
        storage_metrics: &StorageMetrics,
    ) {
        // CPU usage alert
        if metrics.cpu_usage_percent > 90.0 {
            self.raise_alert(Alert {
                id: "high_cpu_usage".to_string(),
                severity: AlertSeverity::Critical,
                component: "system".to_string(),
                message: format!("CPU usage is {:.1}%", metrics.cpu_usage_percent),
                timestamp_tick: dt::tick_index(),
                resolved: false,
            })
            .await;
        }

        // Error rate alert
        if storage_metrics.error_rate > 0.05 {
            self.raise_alert(Alert {
                id: "high_error_rate".to_string(),
                severity: AlertSeverity::Error,
                component: "storage".to_string(),
                message: format!("Error rate is {:.1}%", storage_metrics.error_rate * 100.0),
                timestamp_tick: dt::tick_index(),
                resolved: false,
            })
            .await;
        }
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Operational utilities
pub struct OperationalUtils;

impl OperationalUtils {
    /// Generate system report
    pub async fn generate_system_report(
        health_checks: &[HealthCheck],
        system_metrics: &SystemMetrics,
        storage_metrics: &StorageMetrics,
        alerts: &[Alert],
    ) -> String {
        let overall_health = Self::calculate_overall_health(health_checks);

        format!(
            r#"DSM Storage Node System Report
=====================================

Overall Health: {:?}
Tick: {}

System Metrics:
- CPU Usage: {:.1}%
- Memory Usage: {} MB
- Disk Usage: {} GB
- Uptime: {} ticks
- Active Connections: {}

Storage Metrics:
- Total Objects: {}
- Total Bytes: {} GB
- Operations/tick: {:.4}
- Average Latency: {:.1} ticks
- Error Rate: {:.3}%

Active Alerts: {}
Recent Health Checks: {}

Partition Distribution:
{}
"#,
            overall_health,
            dt::tick_index(),
            system_metrics.cpu_usage_percent,
            system_metrics.memory_usage_bytes / 1024 / 1024,
            system_metrics.disk_usage_bytes / 1024 / 1024 / 1024,
            system_metrics.uptime_ticks,
            system_metrics.active_connections,
            storage_metrics.total_objects,
            storage_metrics.total_bytes / 1024 / 1024 / 1024,
            storage_metrics.operations_per_tick,
            storage_metrics.average_latency_ticks,
            storage_metrics.error_rate,
            alerts.len(),
            health_checks.len(),
            storage_metrics
                .partition_distribution
                .iter()
                .map(|(k, v)| format!("  {}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Calculate overall system health
    pub fn calculate_overall_health(checks: &[HealthCheck]) -> HealthStatus {
        let mut has_critical = false;
        let mut has_unhealthy = false;
        let mut has_degraded = false;

        for check in checks {
            match check.status {
                HealthStatus::Critical => has_critical = true,
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                HealthStatus::Healthy => {}
            }
        }

        if has_critical {
            HealthStatus::Critical
        } else if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(
        system_metrics: &SystemMetrics,
        storage_metrics: &StorageMetrics,
    ) -> String {
        format!(
            r#"# HELP dsm_cpu_usage_percent CPU usage percentage
# TYPE dsm_cpu_usage_percent gauge
dsm_cpu_usage_percent {}

# HELP dsm_memory_usage_bytes Memory usage in bytes
# TYPE dsm_memory_usage_bytes gauge
dsm_memory_usage_bytes {}

# HELP dsm_storage_total_objects Total number of stored objects
# TYPE dsm_storage_total_objects gauge
dsm_storage_total_objects {}

# HELP dsm_storage_operations_per_tick Operations per tick
# TYPE dsm_storage_operations_per_tick gauge
dsm_storage_operations_per_tick {}

# HELP dsm_storage_average_latency_ticks Average operation latency in ticks
# TYPE dsm_storage_average_latency_ticks gauge
dsm_storage_average_latency_ticks {}

# HELP dsm_storage_error_rate Error rate (0.0 to 1.0)
# TYPE dsm_storage_error_rate gauge
dsm_storage_error_rate {}
"#,
            system_metrics.cpu_usage_percent,
            system_metrics.memory_usage_bytes,
            storage_metrics.total_objects,
            storage_metrics.operations_per_tick,
            storage_metrics.average_latency_ticks,
            storage_metrics.error_rate
        )
    }
}

/// Database health check
pub struct DatabaseHealthCheck {
    pub pool: deadpool_postgres::Pool,
}

impl HealthCheckFn for DatabaseHealthCheck {
    fn check(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthCheck> + Send>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let start_tick = dt::tick_index();

            let result = pool.get().await;
            let duration = dt::tick_index().saturating_sub(start_tick);

            match result {
                Ok(client) => {
                    // Test a simple query
                    let query_result = client.query_one("SELECT 1", &[]).await;
                    match query_result {
                        Ok(_) => HealthCheck {
                            component: "database".to_string(),
                            status: HealthStatus::Healthy,
                            message: "Database connection healthy".to_string(),
                            timestamp_tick: dt::tick_index(),
                            duration_ticks: duration,
                        },
                        Err(e) => HealthCheck {
                            component: "database".to_string(),
                            status: HealthStatus::Unhealthy,
                            message: format!("Database query failed: {}", e),
                            timestamp_tick: dt::tick_index(),
                            duration_ticks: duration,
                        },
                    }
                }
                Err(e) => HealthCheck {
                    component: "database".to_string(),
                    status: HealthStatus::Critical,
                    message: format!("Database connection failed: {}", e),
                    timestamp_tick: dt::tick_index(),
                    duration_ticks: duration,
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_checker() {
        let rt = tokio::runtime::Runtime::new()
            .unwrap_or_else(|e| panic!("failed to create runtime: {e}"));
        rt.block_on(async {
            let mut checker = HealthChecker::new();

            checker.register_check("test".to_string(), || async {
                HealthCheck {
                    component: "test".to_string(),
                    status: HealthStatus::Healthy,
                    message: "Test passed".to_string(),
                    timestamp_tick: 1234567890,
                    duration_ticks: 10,
                }
            });

            let results = checker.run_all_checks().await;
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].component, "test");
            assert!(matches!(results[0].status, HealthStatus::Healthy));
        });
    }

    #[test]
    fn test_overall_health_calculation() {
        let checks = vec![
            HealthCheck {
                component: "cpu".to_string(),
                status: HealthStatus::Healthy,
                message: "OK".to_string(),
                timestamp_tick: 0,
                duration_ticks: 0,
            },
            HealthCheck {
                component: "memory".to_string(),
                status: HealthStatus::Degraded,
                message: "High usage".to_string(),
                timestamp_tick: 0,
                duration_ticks: 0,
            },
        ];

        let overall = OperationalUtils::calculate_overall_health(&checks);
        assert!(matches!(overall, HealthStatus::Degraded));
    }
}
