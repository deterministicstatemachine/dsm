//! Durable replication (clockless).
//!
//! This module implements a storage-node-local *reliable multicast* transport helper.
//! It is **not** part of the DSM protocol validity rules; it only improves local
//! operator durability for dev nodes.
//!
//! Key invariants:
//! - No wall-clock time and no `tokio::time` usage.
//! - Deterministic scheduling is driven by an explicit `now_iter` passed in.
//! - Idempotent enqueue (target,idempotency_key) prevents replay storms.
//! - `x-dsm-replicated` header prevents infinite loops.

use crate::db;
use crate::timing::TimingStrategy;
use crate::AppState;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use std::sync::Arc;

/// Parse a deterministic list of dev node ports from the environment.
fn dev_ports() -> Vec<u16> {
    let raw = match std::env::var("DSM_DEV_NODE_PORTS") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Vec::new(),
    };

    raw.split(',')
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .collect()
}

/// Header used to prevent replication loops when dev fanout is enabled.
pub const HDR_REPLICATED: &str = "x-dsm-replicated";

/// Header used as an idempotency key for durable replication.
pub const HDR_IDEMPOTENCY_KEY: &str = "x-dsm-idempotency";

/// Enqueue a replication job to each configured peer.
///
/// This does not perform any network I/O; it only persists jobs into the outbox.
pub async fn fanout_request_durable(
    state: Arc<AppState>,
    method: Method,
    path: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    now_iter: i64,
) {
    // Prevent infinite loops.
    if headers.contains_key(HDR_REPLICATED) {
        return;
    }

    // Require idempotency key for durable replication. If absent, don't enqueue.
    let idem = match headers
        .get(HDR_IDEMPOTENCY_KEY)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            log::debug!(
                "durable replication: missing {} header; skipping",
                HDR_IDEMPOTENCY_KEY
            );
            return;
        }
    };

    // Deterministic header encoding: only include string headers.
    // We store values as raw bytes to preserve exactness.
    let mut hdrs: Vec<(String, Vec<u8>)> = Vec::new();
    for (k, v) in headers.iter() {
        hdrs.push((k.as_str().to_string(), v.as_bytes().to_vec()));
    }
    // Add replicated guard for peer delivery.
    hdrs.push((HDR_REPLICATED.to_string(), b"1".to_vec()));
    let hdr_bytes = db::encode_headers_deterministic(&hdrs);

    // Ports -> targets are deterministic from env.
    for port in dev_ports() {
        let target = format!("http://127.0.0.1:{}", port);
        if let Err(e) = db::replication_outbox_enqueue(
            &state.db_pool,
            db::ReplicationOutboxEnqueueParams {
                target: &target,
                method: method.as_str(),
                path,
                headers: &hdr_bytes,
                body: &body,
                idempotency_key: &idem,
                eligible_iter: now_iter,
            },
        )
        .await
        {
            log::error!(
                "durable replication enqueue failed target={} err={}",
                target,
                e
            );
        }
    }
}

/// Pump due outbox jobs (bounded) for this node, driven by explicit `now_iter`.
///
/// Returns number of successfully delivered jobs.
pub async fn pump_replication_outbox(
    state: Arc<AppState>,
    timing: &dyn TimingStrategy,
    now_iter: i64,
    max_jobs: i64,
) -> i64 {
    let client = Client::new();
    let mut delivered: i64 = 0;
    let rows = match db::replication_outbox_list_due(&state.db_pool, now_iter, max_jobs).await {
        Ok(r) => r,
        Err(e) => {
            log::error!("replication outbox list_due failed: {}", e);
            return 0;
        }
    };

    for row in rows {
        let url = format!("{}{}", row.target, row.path);
        let method = match Method::from_bytes(row.method.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                let _ = db::replication_outbox_record_failure(
                    &state.db_pool,
                    timing,
                    row.id,
                    now_iter,
                    row.attempts.saturating_add(1),
                    "invalid method",
                )
                .await;
                continue;
            }
        };

        let decoded = match db::decode_headers_deterministic(&row.headers) {
            Ok(h) => h,
            Err(e) => {
                let _ = db::replication_outbox_record_failure(
                    &state.db_pool,
                    timing,
                    row.id,
                    now_iter,
                    row.attempts.saturating_add(1),
                    &format!("bad headers: {}", e),
                )
                .await;
                continue;
            }
        };
        let mut hm = HeaderMap::new();
        for (k, v) in decoded {
            // Only accept valid header names/values.
            if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(val) = HeaderValue::from_bytes(&v) {
                    hm.insert(name, val);
                }
            }
        }

        match client
            .request(method, &url)
            .headers(hm)
            .body(row.body.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if db::replication_outbox_mark_done(&state.db_pool, row.id)
                    .await
                    .is_ok()
                {
                    delivered += 1;
                }
            }
            Ok(resp) => {
                let attempts_next = row.attempts.saturating_add(1);
                let _ = db::replication_outbox_record_failure(
                    &state.db_pool,
                    timing,
                    row.id,
                    now_iter,
                    attempts_next,
                    &format!("non-success status {}", resp.status()),
                )
                .await;
            }
            Err(e) => {
                let attempts_next = row.attempts.saturating_add(1);
                let _ = db::replication_outbox_record_failure(
                    &state.db_pool,
                    timing,
                    row.id,
                    now_iter,
                    attempts_next,
                    &format!("send error {}", e),
                )
                .await;
            }
        }
    }

    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn dev_ports_empty_when_env_unset() {
        std::env::remove_var("DSM_DEV_NODE_PORTS");
        assert!(dev_ports().is_empty());
    }

    #[test]
    #[serial]
    fn dev_ports_empty_when_env_blank() {
        std::env::set_var("DSM_DEV_NODE_PORTS", "   ");
        assert!(dev_ports().is_empty());
        std::env::remove_var("DSM_DEV_NODE_PORTS");
    }

    #[test]
    #[serial]
    fn dev_ports_parses_single_port() {
        std::env::set_var("DSM_DEV_NODE_PORTS", "8080");
        assert_eq!(dev_ports(), vec![8080]);
        std::env::remove_var("DSM_DEV_NODE_PORTS");
    }

    #[test]
    #[serial]
    fn dev_ports_parses_multiple_ports() {
        std::env::set_var("DSM_DEV_NODE_PORTS", "8080,8081,8082");
        assert_eq!(dev_ports(), vec![8080, 8081, 8082]);
        std::env::remove_var("DSM_DEV_NODE_PORTS");
    }

    #[test]
    #[serial]
    fn dev_ports_ignores_invalid_entries() {
        std::env::set_var("DSM_DEV_NODE_PORTS", "8080,abc,8082,,9999");
        assert_eq!(dev_ports(), vec![8080, 8082, 9999]);
        std::env::remove_var("DSM_DEV_NODE_PORTS");
    }

    #[test]
    #[serial]
    fn dev_ports_handles_whitespace() {
        std::env::set_var("DSM_DEV_NODE_PORTS", " 8080 , 8081 ");
        assert_eq!(dev_ports(), vec![8080, 8081]);
        std::env::remove_var("DSM_DEV_NODE_PORTS");
    }

    #[test]
    fn hdr_replicated_constant() {
        assert_eq!(HDR_REPLICATED, "x-dsm-replicated");
    }

    #[test]
    fn hdr_idempotency_key_constant() {
        assert_eq!(HDR_IDEMPOTENCY_KEY, "x-dsm-idempotency");
    }
}
