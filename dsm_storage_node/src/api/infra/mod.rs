//! Cross-cutting infrastructure: admin endpoints, hardening helpers,
//! rate-limiting middleware, and network-config detection.

pub mod admin;
pub mod hardening;
pub mod network_config;
pub mod rate_limit;
