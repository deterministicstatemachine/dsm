//! # Portable Logging and Panic Handling
//!
//! Provides platform-adaptive logging (Android logcat via `android_logger`,
//! desktop via `env_logger`) and a chained panic hook that captures Rust
//! panics with full backtraces before forwarding to the previous hook.
//!
//! Log format omits wall-clock unix_tss to comply with the DSM determinism
//! invariant. Structured helper functions (`log_jni_call`, `log_crypto_operation`,
//! `log_bluetooth_operation`, etc.) provide consistent observability across
//! the SDK without coupling to any specific log framework.

use std::sync::Once;
use log::{LevelFilter, info, warn, error, debug};

static LOGGER_INIT: Once = Once::new();
static PANIC_HOOK_INIT: Once = Once::new();

#[cfg(target_os = "android")]
fn init_backend() {
    use android_logger::FilterBuilder;
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(LevelFilter::Debug)
            .with_tag("DSM_RUST")
            .with_filter(FilterBuilder::new().parse("debug").build()),
    );
}

#[cfg(not(target_os = "android"))]
fn init_backend() {
    use std::io::Write;

    let mut b = env_logger::Builder::from_default_env();
    b.filter_level(LevelFilter::Info);
    // Allow RUST_LOG to raise/lower; default to info if unset.
    if std::env::var("RUST_LOG").is_err() {
        b.filter_module("dsm", LevelFilter::Info);
        b.filter_module("dsm_sdk", LevelFilter::Info);
    }
    // NOTE: No wall-clock markers in logs (determinism + repo policy).
    b.format(|buf, record| writeln!(buf, "[{}] {}", record.level(), record.args()));
    let _ = b.try_init();
}

pub fn init_android_device_logging() {
    LOGGER_INIT.call_once(|| {
        init_backend();
        log_initialization_info();
    });
}

fn log_initialization_info() {
    info!("=== DSM Rust Logging Initialized ===");
    info!("Target OS: {0}", std::env::consts::OS);
    info!("Arch    : {0}", std::env::consts::ARCH);
    info!("Package : {0}", env!("CARGO_PKG_NAME"));
    info!("Version : {0}", env!("CARGO_PKG_VERSION"));
    #[cfg(debug_assertions)]
    info!("Build   : Debug");
    #[cfg(not(debug_assertions))]
    info!("Build   : Release");
}

pub fn log_library_loading(library_name: &str, success: bool, error_msg: Option<&str>) {
    if success {
        info!("✅ Native library loaded: {library_name}");
    } else {
        error!(
            "❌ Native library load FAILED: {library_name} — {}",
            error_msg.unwrap_or("unknown")
        );
    }
}

pub fn log_jni_call(
    method: &str,
    params: Option<&str>,
    result: Option<&str>,
    duration_ms: Option<u64>,
) {
    let mut msg = format!("JNI Call: {method}");
    if let Some(p) = params {
        msg.push_str(&format!(" | params={p}"));
    }
    if let Some(r) = result {
        msg.push_str(&format!(" | result={r}"));
    }
    if let Some(d) = duration_ms {
        msg.push_str(&format!(" | {d}ms"));
    }
    debug!("{msg}");
}

pub fn log_performance_metric(op: &str, duration_ms: u64, details: Option<&str>) {
    let mut msg = format!("⏱️ perf {op}={duration_ms}ms");
    if let Some(d) = details {
        msg.push_str(&format!(" | {d}"));
    }
    info!("{msg}");
}
pub fn log_crypto_operation(op: &str, alg: Option<&str>, ok: bool, ms: Option<u64>) {
    let status = if ok { "✅" } else { "❌" };
    let mut msg = format!("{status} crypto: {op}");
    if let Some(a) = alg {
        msg.push_str(&format!(" ({a})"));
    }
    if let Some(d) = ms {
        msg.push_str(&format!(" | {d}ms"));
    }
    if ok {
        info!("{msg}")
    } else {
        warn!("{msg}")
    }
}
pub fn log_bluetooth_operation(op: &str, dev: Option<&str>, ok: bool) {
    let status = if ok { "✅" } else { "❌" };
    let mut msg = format!("{status} bt: {op}");
    if let Some(d) = dev {
        msg.push_str(&format!(" | dev={d}"));
    }
    if ok {
        info!("{msg}")
    } else {
        warn!("{msg}")
    }
}
pub fn log_dsm_operation(op: &str, state: Option<&str>, ok: bool, details: Option<&str>) {
    let status = if ok { "✅" } else { "❌" };
    let mut msg = format!("{status} dsm: {op}");
    if let Some(s) = state {
        msg.push_str(&format!(" | state={s}"));
    }
    if let Some(d) = details {
        msg.push_str(&format!(" | {d}"));
    }
    if ok {
        info!("{msg}")
    } else {
        error!("{msg}")
    }
}
pub fn log_network_operation(op: &str, endpoint: Option<&str>, ok: bool, ms: Option<u64>) {
    let status = if ok { "✅" } else { "❌" };
    let mut msg = format!("{status} net: {op}");
    if let Some(ep) = endpoint {
        msg.push_str(&format!(" | {ep}"));
    }
    if let Some(d) = ms {
        msg.push_str(&format!(" | {d}ms"));
    }
    if ok {
        debug!("{msg}")
    } else {
        warn!("{msg}")
    }
}

pub fn init_panic_handler() {
    PANIC_HOOK_INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            error!("🦀💥 RUST PANIC: {info}");
            let bt = std::backtrace::Backtrace::capture();
            error!("Backtrace:\n{bt}");
            prev(info);
        }));
        info!("Rust panic handler initialized (chained).");
    });
}

// Lightweight macros retained for compatibility
#[macro_export]
macro_rules! device_log {
    (info, $($arg:tt)*) => { log::info!($($arg)*); };
    (warn, $($arg:tt)*) => { log::warn!($($arg)*); };
    (error, $($arg:tt)*) => { log::error!($($arg)*); };
    (debug, $($arg:tt)*) => { log::debug!($($arg)*); };
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── init functions ─────────────────────────────────────────────

    #[test]
    fn init_logging_does_not_panic() {
        init_android_device_logging();
    }

    #[test]
    fn init_logging_idempotent() {
        init_android_device_logging();
        init_android_device_logging();
    }

    #[test]
    fn init_panic_handler_does_not_panic() {
        init_panic_handler();
    }

    #[test]
    fn init_panic_handler_idempotent() {
        init_panic_handler();
        init_panic_handler();
    }

    // ── log_library_loading ────────────────────────────────────────

    #[test]
    fn log_library_loading_success() {
        log_library_loading("libfoo.so", true, None);
    }

    #[test]
    fn log_library_loading_failure() {
        log_library_loading("libbar.so", false, Some("dlopen failed"));
    }

    #[test]
    fn log_library_loading_failure_no_msg() {
        log_library_loading("libbar.so", false, None);
    }

    // ── log_jni_call ───────────────────────────────────────────────

    #[test]
    fn log_jni_call_minimal() {
        log_jni_call("nativeInit", None, None, None);
    }

    #[test]
    fn log_jni_call_full() {
        log_jni_call("nativeTransfer", Some("amount=100"), Some("ok"), Some(42));
    }

    #[test]
    fn log_jni_call_partial_params() {
        log_jni_call("doWork", Some("key=val"), None, Some(10));
    }

    // ── log_performance_metric ─────────────────────────────────────

    #[test]
    fn log_performance_metric_without_details() {
        log_performance_metric("hash_computation", 15, None);
    }

    #[test]
    fn log_performance_metric_with_details() {
        log_performance_metric("serialize", 3, Some("1024 bytes"));
    }

    // ── log_crypto_operation ───────────────────────────────────────

    #[test]
    fn log_crypto_success() {
        log_crypto_operation("sign", Some("Ed25519"), true, Some(5));
    }

    #[test]
    fn log_crypto_failure() {
        log_crypto_operation("verify", None, false, None);
    }

    #[test]
    fn log_crypto_all_none() {
        log_crypto_operation("keygen", None, true, None);
    }

    // ── log_bluetooth_operation ────────────────────────────────────

    #[test]
    fn log_bluetooth_success() {
        log_bluetooth_operation("connect", Some("AA:BB:CC"), true);
    }

    #[test]
    fn log_bluetooth_failure() {
        log_bluetooth_operation("disconnect", None, false);
    }

    // ── log_dsm_operation ──────────────────────────────────────────

    #[test]
    fn log_dsm_operation_success() {
        log_dsm_operation("advance_state", Some("state=42"), true, Some("fast path"));
    }

    #[test]
    fn log_dsm_operation_failure() {
        log_dsm_operation("validate", None, false, None);
    }

    #[test]
    fn log_dsm_operation_partial() {
        log_dsm_operation("genesis", Some("init"), true, None);
    }

    // ── log_network_operation ──────────────────────────────────────

    #[test]
    fn log_network_success() {
        log_network_operation("POST", Some("/api/submit"), true, Some(200));
    }

    #[test]
    fn log_network_failure() {
        log_network_operation("GET", None, false, None);
    }

    #[test]
    fn log_network_partial() {
        log_network_operation("PUT", Some("/api/update"), false, Some(500));
    }

    // ── device_log macro ───────────────────────────────────────────

    #[test]
    fn device_log_macro_all_levels() {
        device_log!(info, "test info {}", 1);
        device_log!(warn, "test warn");
        device_log!(error, "test error {}", "msg");
        device_log!(debug, "test debug");
    }

    // ── edge cases: empty strings ──────────────────────────────────

    #[test]
    fn log_jni_call_empty_method() {
        log_jni_call("", None, None, None);
    }

    #[test]
    fn log_library_loading_empty_name() {
        log_library_loading("", true, None);
        log_library_loading("", false, Some(""));
    }

    #[test]
    fn log_performance_metric_zero_duration() {
        log_performance_metric("op", 0, None);
    }

    #[test]
    fn log_crypto_empty_op() {
        log_crypto_operation("", None, true, Some(0));
        log_crypto_operation("", Some(""), false, None);
    }

    #[test]
    fn log_bluetooth_empty_fields() {
        log_bluetooth_operation("", Some(""), true);
        log_bluetooth_operation("", None, false);
    }

    #[test]
    fn log_dsm_operation_all_none() {
        log_dsm_operation("", None, true, None);
        log_dsm_operation("", None, false, None);
    }

    #[test]
    fn log_network_operation_all_fields() {
        log_network_operation("DELETE", Some("/api/resource"), true, Some(0));
    }

    #[test]
    fn log_network_operation_all_none() {
        log_network_operation("", None, true, None);
        log_network_operation("", None, false, None);
    }

    // ── combined init ──────────────────────────────────────────────

    #[test]
    fn init_both_logging_and_panic_handler() {
        init_android_device_logging();
        init_panic_handler();
        init_android_device_logging();
        init_panic_handler();
    }

    // ── unicode / special characters ───────────────────────────────

    #[test]
    fn log_jni_call_unicode() {
        log_jni_call("日本語メソッド", Some("키=값"), Some("résultat"), Some(999));
    }

    #[test]
    fn log_performance_metric_large_duration() {
        log_performance_metric("heavy_op", u64::MAX, Some("max duration"));
    }

    #[test]
    fn log_dsm_operation_with_all_fields() {
        log_dsm_operation("full_op", Some("state=ready"), true, Some("detail=extra"));
        log_dsm_operation("full_op", Some("state=broken"), false, Some("detail=crash"));
    }
}
