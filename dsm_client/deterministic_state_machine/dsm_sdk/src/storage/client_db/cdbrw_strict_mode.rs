// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict-mode toggle for hardware-bound K_DBRW derivation (Issue #213).
//!
//! When ON, every genesis-bootstrap path that derives K_DBRW MUST supply
//! real hardware entropy + environment fingerprint material — the
//! `derive_bootstrap_k_dbrw` placeholder path (whose own docstring
//! disclaims silicon binding) is rejected with a structured error.
//!
//! When OFF (the default during pre-mainnet development), genesis paths
//! fall back to `derive_bootstrap_k_dbrw` with a warning log so cloned-
//! device protections are NOT yet enforced — an explicit acceptance of
//! the documented gap.
//!
//! Mainnet deployments MUST flip this to ON before accepting traffic.
//! Doing so will cause every genesis attempt to FAIL with a structured
//! error until platform-specific hardware-entropy collectors are wired
//! at all four production call sites:
//!
//!   * `handlers/bootstrap_adapter.rs`
//!   * `sdk/identity_sdk.rs`
//!   * `sdk/core_sdk.rs`
//!   * `sdk/counterparty_genesis_helpers.rs`
//!
//! The platform integration contract is documented in the issue: each
//! call site must collect a non-trivial hardware-entropy blob and an
//! environment-fingerprint blob from its target platform (Android JNI,
//! iOS FFI, etc.) and feed them into
//! `dsm::crypto::cdbrw_binding::derive_cdbrw_binding_key`.

use anyhow::{anyhow, Result};
use rusqlite::{params, OptionalExtension};

use super::get_connection;

const STRICT_DBRW_KEY: &str = "strict_dbrw_hardware_binding";

/// Read the strict-DBRW-hardware-binding flag. Returns `false`
/// (fail-open transitional) by default if the setting has never been
/// written.
pub fn is_strict_dbrw_hardware_binding() -> Result<bool> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    let val: Option<String> = conn
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![STRICT_DBRW_KEY],
            |row| row.get(0),
        )
        .optional()?;
    Ok(val.as_deref() == Some("1"))
}

/// Enable or disable strict hardware-bound K_DBRW mode. **Mainnet
/// deployments MUST call `set_strict_dbrw_hardware_binding(true)`
/// before accepting production traffic.** Until platform-specific
/// hardware-entropy collectors are wired through the four production
/// genesis call sites (Issue #213), flipping this to `true` will
/// cause every new-genesis attempt to fail-closed.
pub fn set_strict_dbrw_hardware_binding(enabled: bool) -> Result<()> {
    let binding = get_connection()?;
    let conn = binding
        .lock()
        .map_err(|_| anyhow!("Database lock poisoned - concurrent access error"))?;
    conn.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?1, ?2)",
        params![STRICT_DBRW_KEY, if enabled { "1" } else { "0" }],
    )?;
    Ok(())
}

/// Reject a bootstrap-tagged K_DBRW derivation when strict mode is on.
///
/// Each of the four production genesis call sites should call this
/// helper IMMEDIATELY before invoking
/// `dsm::crypto::cdbrw_binding::derive_bootstrap_k_dbrw`. When strict
/// mode is ON and no real hardware-entropy collector is wired in, this
/// returns a structured error that surfaces all the way back to the
/// frontend. When strict mode is OFF, returns `Ok(())` so the
/// bootstrap path proceeds with a documented placeholder K_DBRW.
///
/// `call_site` is a short identifier (e.g., `"bootstrap_adapter"`)
/// that goes into the error message so the operator can see which
/// genesis path failed.
pub fn enforce_strict_dbrw_or_proceed(call_site: &str) -> Result<(), dsm::types::error::DsmError> {
    match is_strict_dbrw_hardware_binding() {
        Ok(true) => Err(dsm::types::error::DsmError::invalid_operation(format!(
            "strict DBRW hardware-binding mode is ON but call site `{call_site}` has not been \
             wired to a real hardware-entropy collector yet — Issue #213. Refusing to derive a \
             bootstrap-tagged K_DBRW that lacks silicon binding. Either flip strict mode OFF \
             (development only) or wire the platform-specific hardware-entropy collector at \
             this call site."
        ))),
        Ok(false) => {
            log::warn!(
                "[CDBRW] strict hardware-binding mode is OFF — call site `{call_site}` is using \
                 bootstrap-tagged K_DBRW (NOT silicon-bound). Anti-cloning guarantees per \
                 whitepaper §12 are NOT yet enforced. Mainnet must flip strict mode on before \
                 accepting traffic. (Issue #213)"
            );
            Ok(())
        }
        Err(e) => {
            // Database error reading the flag — fail-closed by treating
            // as "strict mode unknown, refuse." Operator must repair
            // their settings store before genesis can proceed.
            Err(dsm::types::error::DsmError::invalid_operation(format!(
                "strict DBRW hardware-binding mode lookup failed for call site `{call_site}`: \
                 {e}. Refusing to proceed with K_DBRW derivation."
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn init_test_db() {
        unsafe { std::env::set_var("DSM_SDK_TEST_MODE", "1") };
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init db");
    }

    #[test]
    #[serial]
    fn strict_dbrw_default_off() {
        init_test_db();
        assert!(!is_strict_dbrw_hardware_binding().unwrap());
    }

    #[test]
    #[serial]
    fn strict_dbrw_set_and_read() {
        init_test_db();
        assert!(!is_strict_dbrw_hardware_binding().unwrap());

        set_strict_dbrw_hardware_binding(true).unwrap();
        assert!(is_strict_dbrw_hardware_binding().unwrap());

        set_strict_dbrw_hardware_binding(false).unwrap();
        assert!(!is_strict_dbrw_hardware_binding().unwrap());
    }

    #[test]
    #[serial]
    fn enforce_returns_ok_when_strict_off() {
        init_test_db();
        set_strict_dbrw_hardware_binding(false).unwrap();
        assert!(enforce_strict_dbrw_or_proceed("test_site").is_ok());
    }

    /// Issue #213 regression: flipping strict mode on MUST cause every
    /// bootstrap-tagged K_DBRW call site to fail-closed. The structured
    /// error names the call site so an operator can identify which
    /// genesis path needs platform-collector wiring.
    #[test]
    #[serial]
    fn enforce_returns_strict_error_when_strict_on() {
        init_test_db();
        set_strict_dbrw_hardware_binding(true).unwrap();
        let result = enforce_strict_dbrw_or_proceed("test_site");
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("strict DBRW hardware-binding"),
            "error must reference strict mode, got: {err_msg}"
        );
        assert!(
            err_msg.contains("test_site"),
            "error must name the call site, got: {err_msg}"
        );
        assert!(
            err_msg.contains("Issue #213"),
            "error must reference the tracking issue, got: {err_msg}"
        );

        // Reset so subsequent tests aren't affected.
        set_strict_dbrw_hardware_binding(false).unwrap();
    }
}
