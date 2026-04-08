// SPDX-License-Identifier: MIT OR Apache-2.0
//! Miscellaneous route handlers for AppRouterImpl.
//!
//! Handles `debug.dump_state`, `debug.trigger_genesis` (query),
//! `dbrw.status` (query), and `ble.command` (invoke).

use dsm::types::proto as generated;
use prost::Message;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::security::cdbrw_verifier::read_verifier_public_key_if_present;
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{pack_envelope_ok, pack_bytes_ok, err};

const CDBRW_ENROLLMENT_FILE: &str = "dsm_silicon_fp_v4.bin";
const PREFIX_BYTES: usize = 10;

#[derive(Debug, Clone, PartialEq)]
struct DbrwEnrollmentSnapshot {
    revision: u32,
    arena_bytes: u32,
    probes: u32,
    steps_per_probe: u32,
    histogram_bins: u32,
    rotation_bits: u32,
    epsilon_intra: f32,
    mean_histogram_len: u32,
    reference_anchor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Default)]
struct DbrwRuntimeSnapshot {
    runtime_metrics_present: bool,
    runtime_access_level: String,
    runtime_trust_score: f32,
    runtime_health_check_ran: bool,
    runtime_health_check_passed: bool,
    runtime_h_hat: f32,
    runtime_rho_hat: f32,
    runtime_l_hat: f32,
    runtime_match_score: f32,
    runtime_w1_distance: f32,
    runtime_w1_threshold: f32,
    runtime_anchor_prefix: Vec<u8>,
    runtime_error: String,
}

const CDBRW_RUNTIME_SNAPSHOT_VERSION: u32 = 1;
const CDBRW_RUNTIME_FLAG_RUNTIME_AVAILABLE: u32 = 1 << 0;
const CDBRW_RUNTIME_FLAG_HEALTH_RAN: u32 = 1 << 3;
const CDBRW_RUNTIME_FLAG_HEALTH_PASSED: u32 = 1 << 4;

/// C-DBRW spec §4.5.5: h_min = 0.5 bits/sample (Normative Requirement)
const H_MIN: f32 = 0.5;
/// C-DBRW spec §4.5.7: Ĥ threshold = h_min - ε, with ε = 0.05
const H_HAT_MIN: f32 = 0.45;
/// C-DBRW spec §4.5.7: |ρ̂| ≤ 0.3 (Definition 4.15 condition ii)
const RHO_HAT_MAX: f32 = 0.3;
/// C-DBRW spec §4.5.7: L̂ threshold = h_min - ε
const L_HAT_MIN: f32 = 0.45;
/// C-DBRW spec Remark 4.6: conservative floor for adapted mixing
const H0_ADAPTED_FLOOR: f32 = 0.25;

fn take_prefix(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(PREFIX_BYTES).collect()
}

/// Compute C-DBRW resonant health tier from raw entropy metrics.
///
/// Implements the tri-layer assessment from C-DBRW spec §7:
///   - **PASS**: All 3 conditions of Definition 4.15 are met.
///   - **RESONANT**: ρ exceeds raw threshold but effective entropy rate h₀_eff ≥ h_min.
///     Per Theorem 8.1(ii), thermal drift *strengthens* the fingerprint.
///   - **ADAPTED**: h₀_eff below h_min but ≥ adapted floor; longer orbits compensate (Remark 4.6).
///   - **FAIL**: Fundamental entropy collapse (Ĥ or L̂ below threshold).
fn compute_resonant_health(h_hat: f32, rho_hat: f32, l_hat: f32) -> (&'static str, f32, u32) {
    let h0_eff = h_hat * (1.0 - rho_hat.abs());
    let base_pass = h_hat >= H_HAT_MIN && rho_hat.abs() <= RHO_HAT_MAX && l_hat >= L_HAT_MIN;
    let entropy_ok = h_hat >= H_HAT_MIN && l_hat >= L_HAT_MIN;

    let (status, recommended_n) = if base_pass {
        ("PASS", 4096u32)
    } else if entropy_ok && h0_eff >= H_MIN {
        // Theorem 8.1(ii): thermal coupling strengthens fingerprint
        ("RESONANT", 4096)
    } else if entropy_ok && h0_eff >= H0_ADAPTED_FLOOR {
        // Remark 4.6: autocorrelated mixing needs N ≥ 16384 for strong convergence
        let n = if h0_eff >= 0.4 { 8192u32 } else { 16384 };
        ("ADAPTED", n)
    } else {
        ("FAIL", 16384)
    };

    (status, h0_eff, recommended_n)
}

fn read_u32_be(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("read {field}: {e}"))?;
    Ok(u32::from_be_bytes(buf))
}

fn read_f32_be(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<f32, String> {
    let mut buf = [0u8; 4];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("read {field}: {e}"))?;
    Ok(f32::from_bits(u32::from_be_bytes(buf)))
}

fn read_len_prefixed_bytes(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<Vec<u8>, String> {
    let len = read_u32_be(cursor, field)? as usize;
    let mut bytes = vec![0u8; len];
    cursor
        .read_exact(&mut bytes)
        .map_err(|e| format!("read {field}: {e}"))?;
    Ok(bytes)
}

fn read_len_prefixed_string(cursor: &mut Cursor<&[u8]>, field: &str) -> Result<String, String> {
    let bytes = read_len_prefixed_bytes(cursor, field)?;
    String::from_utf8(bytes).map_err(|e| format!("decode {field}: {e}"))
}

fn load_cdbrw_enrollment(base_dir: &Path) -> Result<Option<DbrwEnrollmentSnapshot>, String> {
    let path = base_dir.join(CDBRW_ENROLLMENT_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&path).map_err(|e| format!("read {:?}: {e}", path))?;
    let mut cursor = Cursor::new(bytes.as_slice());

    let revision = read_u32_be(&mut cursor, "revision")?;
    let arena_bytes = read_u32_be(&mut cursor, "arena_bytes")?;
    let probes = read_u32_be(&mut cursor, "probes")?;
    let steps_per_probe = read_u32_be(&mut cursor, "steps_per_probe")?;
    let histogram_bins = read_u32_be(&mut cursor, "histogram_bins")?;
    let rotation_bits = read_u32_be(&mut cursor, "rotation_bits")?;
    let epsilon_intra = read_f32_be(&mut cursor, "epsilon_intra")?;
    let mean_histogram_len = read_u32_be(&mut cursor, "mean_histogram_len")?;

    let histogram_bytes = mean_histogram_len
        .checked_mul(4)
        .ok_or_else(|| "mean_histogram_len overflow".to_string())?;
    let mut scratch = vec![0u8; histogram_bytes as usize];
    cursor
        .read_exact(&mut scratch)
        .map_err(|e| format!("read mean_histogram: {e}"))?;

    let anchor_len = read_u32_be(&mut cursor, "reference_anchor_len")?;
    let mut reference_anchor = vec![0u8; anchor_len as usize];
    cursor
        .read_exact(&mut reference_anchor)
        .map_err(|e| format!("read reference_anchor: {e}"))?;

    Ok(Some(DbrwEnrollmentSnapshot {
        revision,
        arena_bytes,
        probes,
        steps_per_probe,
        histogram_bins,
        rotation_bits,
        epsilon_intra,
        mean_histogram_len,
        reference_anchor,
    }))
}

fn parse_android_cdbrw_runtime_snapshot(bytes: &[u8]) -> Result<DbrwRuntimeSnapshot, String> {
    let mut cursor = Cursor::new(bytes);
    let version = read_u32_be(&mut cursor, "runtime_version")?;
    if version != CDBRW_RUNTIME_SNAPSHOT_VERSION {
        return Err(format!("unsupported runtime snapshot version: {version}"));
    }

    let flags = read_u32_be(&mut cursor, "runtime_flags")?;
    let runtime_trust_score = read_f32_be(&mut cursor, "runtime_trust_score")?;
    let runtime_match_score = read_f32_be(&mut cursor, "runtime_match_score")?;
    let runtime_w1_distance = read_f32_be(&mut cursor, "runtime_w1_distance")?;
    let runtime_w1_threshold = read_f32_be(&mut cursor, "runtime_w1_threshold")?;
    let runtime_h_hat = read_f32_be(&mut cursor, "runtime_h_hat")?;
    let runtime_rho_hat = read_f32_be(&mut cursor, "runtime_rho_hat")?;
    let runtime_l_hat = read_f32_be(&mut cursor, "runtime_l_hat")?;
    let runtime_anchor_prefix = read_len_prefixed_bytes(&mut cursor, "runtime_anchor_prefix")?;
    let runtime_access_level = read_len_prefixed_string(&mut cursor, "runtime_access_level")?;
    let runtime_error = read_len_prefixed_string(&mut cursor, "runtime_error")?;

    Ok(DbrwRuntimeSnapshot {
        runtime_metrics_present: (flags & CDBRW_RUNTIME_FLAG_RUNTIME_AVAILABLE) != 0,
        runtime_access_level,
        runtime_trust_score,
        runtime_health_check_ran: (flags & CDBRW_RUNTIME_FLAG_HEALTH_RAN) != 0,
        runtime_health_check_passed: (flags & CDBRW_RUNTIME_FLAG_HEALTH_PASSED) != 0,
        runtime_h_hat,
        runtime_rho_hat,
        runtime_l_hat,
        runtime_match_score,
        runtime_w1_distance,
        runtime_w1_threshold,
        runtime_anchor_prefix,
        runtime_error,
    })
}

#[cfg(target_os = "android")]
fn current_cdbrw_binding_key() -> Option<Vec<u8>> {
    crate::jni::cdbrw::get_cdbrw_binding_key()
}

#[cfg(not(target_os = "android"))]
fn current_cdbrw_binding_key() -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "android")]
fn current_android_cdbrw_runtime_snapshot() -> Result<Option<DbrwRuntimeSnapshot>, String> {
    crate::jni::jni_common::with_env(|env| {
        let mut env = unsafe { jni::JNIEnv::from_raw(env.get_raw() as *mut _) }
            .map_err(|e| format!("clone JNIEnv failed: {e}"))?;
        let class = crate::jni::jni_common::find_class_with_app_loader(
            &mut env,
            "com/dsm/wallet/bridge/Unified",
        )?;
        let value = env
            .call_static_method(class, "getCdbrwRuntimeSnapshot", "()[B", &[])
            .map_err(|e| format!("getCdbrwRuntimeSnapshot failed: {e}"))?;
        let bytes = crate::jni::jni_common::jvalue_bytearray_to_vec(&env, value)?;
        if bytes.is_empty() {
            return Ok(None);
        }
        parse_android_cdbrw_runtime_snapshot(&bytes).map(Some)
    })
}

#[cfg(not(target_os = "android"))]
fn current_android_cdbrw_runtime_snapshot() -> Result<Option<DbrwRuntimeSnapshot>, String> {
    Ok(None)
}

impl AppRouterImpl {
    /// Dispatch handler for `debug.dump_state` and `debug.trigger_genesis` query routes.
    pub(crate) async fn handle_debug_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "debug.dump_state" => {
                // Forensic: dump entire in-memory state to logs (sensitive!)
                // Must be explicitly enabled with a query param: ?enable_debug_dump=1
                if !q.params.is_empty() && q.params == b"enable_debug_dump=1" {
                    use crate::sdk::app_state::AppState;
                    use crate::storage::client_db::{get_all_contacts, get_wallet_state};

                    // Dump AppState (forensic: sensitive!)
                    let device_id = AppState::get_device_id().unwrap_or_default();
                    let genesis_hash = AppState::get_genesis_hash().unwrap_or_default();
                    let public_key = AppState::get_public_key().unwrap_or_default();
                    let smt_root = AppState::get_smt_root().unwrap_or_default();
                    log::info!("[DEBUG_DUMP] AppState:");
                    log::info!(
                        "[DEBUG_DUMP] - device_id: {}",
                        crate::util::text_id::encode_base32_crockford(&device_id)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - genesis_hash: {}",
                        crate::util::text_id::encode_base32_crockford(&genesis_hash)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - public_key: {}",
                        crate::util::text_id::encode_base32_crockford(&public_key)
                    );
                    log::info!(
                        "[DEBUG_DUMP] - smt_root: {}",
                        crate::util::text_id::encode_base32_crockford(&smt_root)
                    );

                    // Dump all contacts (forensic: sensitive!)
                    match get_all_contacts() {
                        Ok(contacts) => {
                            log::info!("[DEBUG_DUMP] Contacts ({}):", contacts.len());
                            for c in contacts {
                                log::info!(
                                    "[DEBUG_DUMP] - {}: device_id={}, genesis_hash={}",
                                    c.alias,
                                    crate::util::text_id::encode_base32_crockford(&c.device_id),
                                    crate::util::text_id::encode_base32_crockford(&c.genesis_hash)
                                );
                            }
                        }
                        Err(e) => log::warn!("[DEBUG_DUMP] Failed to dump contacts: {}", e),
                    }

                    // Dump wallet state (forensic: sensitive!)
                    let device_id_txt =
                        crate::util::text_id::encode_base32_crockford(&self.device_id_bytes);
                    match get_wallet_state(&device_id_txt) {
                        Ok(state) => {
                            log::info!("[DEBUG_DUMP] WalletState:");
                            log::info!("[DEBUG_DUMP] - state: {:?}", state);
                        }
                        Err(e) => log::warn!("[DEBUG_DUMP] Failed to dump wallet state: {}", e),
                    }

                    pack_bytes_ok(
                        b"debug dump complete".to_vec(),
                        generated::Hash32 { v: vec![0u8; 32] },
                    )
                } else {
                    err("debug.dump_state requires ?enable_debug_dump=1".into())
                }
            }

            // -------- debug.trigger_genesis --------
            "debug.trigger_genesis" => {
                // Forensic: trigger a new genesis (MPC) from an existing device
                // WARNING: this is a destructive operation that resets state!
                if !q.params.is_empty() && q.params == b"enable_debug_genesis=1" {
                    // Get device identity (MUST be valid)
                    let device_id = match crate::sdk::app_state::AppState::get_device_id() {
                        Some(dev) if dev.len() == 32 => dev,
                        _ => {
                            return err("debug.trigger_genesis: invalid or missing device_id".into())
                        }
                    };
                    let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);

                    // Confirm with the user (forensic: sensitive!)
                    log::warn!("[DEBUG_GENESIS] WARNING: This will RESET the device state and TRIGGER A NEW GENESIS!");
                    log::warn!("[DEBUG_GENESIS] Device ID (b32): {}", device_id_b32);
                    log::warn!("[DEBUG_GENESIS] To proceed, re-send this request with ?enable_debug_genesis=1");

                    err("debug.trigger_genesis: awaiting confirmation".into())
                } else {
                    err("debug.trigger_genesis requires ?enable_debug_genesis=1".into())
                }
            }

            other => err(format!("unknown debug query: {other}")),
        }
    }

    /// Dispatch handler for `dbrw.status` query routes.
    pub(crate) async fn handle_dbrw_query(&self, q: AppQuery) -> AppResult {
        match q.path.as_str() {
            "dbrw.status" => {
                let storage_base_dir = crate::storage_utils::get_storage_base_dir();
                let binding_key = current_cdbrw_binding_key();
                let verifier_public_key = read_verifier_public_key_if_present()
                    .ok()
                    .flatten()
                    .unwrap_or_default();

                // Only run the heavy runtime snapshot (9 derive trials + health
                // capture) when the caller explicitly requests it via params=b"live".
                // Default (empty params) returns stored enrollment data only — instant.
                let wants_live = !q.params.is_empty() && q.params == b"live";

                let mut status_note = if wants_live {
                    "Running live runtime health check…".to_string()
                } else {
                    "Stored enrollment data only. Use live param for runtime health check."
                        .to_string()
                };
                let runtime_snapshot = if wants_live {
                    match current_android_cdbrw_runtime_snapshot() {
                        Ok(snapshot) => snapshot,
                        Err(e) => {
                            status_note = format!("Runtime snapshot failed: {e}");
                            None
                        }
                    }
                } else {
                    None
                };

                let enrollment = match storage_base_dir.as_ref() {
                    Some(base_dir) => match load_cdbrw_enrollment(base_dir) {
                        Ok(enrollment) => enrollment,
                        Err(e) => {
                            status_note = format!("Enrollment parse failed: {e}");
                            None
                        }
                    },
                    None => {
                        status_note =
                            "Storage base directory is not initialized; enrollment snapshot unavailable."
                                .to_string();
                        None
                    }
                };

                if let Some(runtime) = runtime_snapshot.as_ref() {
                    if runtime.runtime_metrics_present {
                        status_note = if runtime.runtime_error.is_empty() {
                            "Live Android runtime metrics included in this snapshot.".to_string()
                        } else {
                            format!(
                                "Live Android runtime metrics included with warnings: {}",
                                runtime.runtime_error
                            )
                        };
                    }
                }

                // Derive resonant health tier from raw entropy metrics (C-DBRW spec §4.5.4, §7, §8.1)
                let rt_h_hat = runtime_snapshot
                    .as_ref()
                    .map(|v| v.runtime_h_hat)
                    .unwrap_or(0.0);
                let rt_rho_hat = runtime_snapshot
                    .as_ref()
                    .map(|v| v.runtime_rho_hat)
                    .unwrap_or(0.0);
                let rt_l_hat = runtime_snapshot
                    .as_ref()
                    .map(|v| v.runtime_l_hat)
                    .unwrap_or(0.0);
                let health_ran = runtime_snapshot
                    .as_ref()
                    .map(|v| v.runtime_health_check_ran)
                    .unwrap_or(false);

                let (resonant_status, h0_eff, recommended_n) = if health_ran {
                    compute_resonant_health(rt_h_hat, rt_rho_hat, rt_l_hat)
                } else {
                    ("NOT_RUN", 0.0f32, 4096u32)
                };

                let runtime_access_level = runtime_snapshot
                    .as_ref()
                    .map(|v| v.runtime_access_level.clone())
                    .unwrap_or_else(|| match resonant_status {
                        "PASS" | "RESONANT" => "FULL_ACCESS".to_string(),
                        "ADAPTED" => "PIN_REQUIRED".to_string(),
                        "FAIL" => "READ_ONLY".to_string(),
                        _ => String::new(),
                    });

                let response = generated::DbrwStatusResponse {
                    enrolled: enrollment.is_some(),
                    binding_key_present: binding_key.is_some(),
                    verifier_keypair_present: !verifier_public_key.is_empty(),
                    storage_base_dir_set: storage_base_dir.is_some(),
                    enrollment_revision: enrollment.as_ref().map(|v| v.revision).unwrap_or(0),
                    arena_bytes: enrollment.as_ref().map(|v| v.arena_bytes).unwrap_or(0),
                    probes: enrollment.as_ref().map(|v| v.probes).unwrap_or(0),
                    steps_per_probe: enrollment.as_ref().map(|v| v.steps_per_probe).unwrap_or(0),
                    histogram_bins: enrollment.as_ref().map(|v| v.histogram_bins).unwrap_or(0),
                    rotation_bits: enrollment.as_ref().map(|v| v.rotation_bits).unwrap_or(0),
                    epsilon_intra: enrollment.as_ref().map(|v| v.epsilon_intra).unwrap_or(0.0),
                    mean_histogram_len: enrollment
                        .as_ref()
                        .map(|v| v.mean_histogram_len)
                        .unwrap_or(0),
                    reference_anchor_prefix: enrollment
                        .as_ref()
                        .map(|v| take_prefix(&v.reference_anchor))
                        .unwrap_or_default(),
                    binding_key_prefix: binding_key.as_deref().map(take_prefix).unwrap_or_default(),
                    verifier_public_key_prefix: take_prefix(&verifier_public_key),
                    verifier_public_key_len: verifier_public_key.len() as u32,
                    storage_base_dir: storage_base_dir
                        .map(|v| v.display().to_string())
                        .unwrap_or_default(),
                    status_note,
                    runtime_metrics_present: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_metrics_present)
                        .unwrap_or(false),
                    runtime_access_level,
                    runtime_trust_score: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_trust_score)
                        .unwrap_or(0.0),
                    runtime_health_check_ran: health_ran,
                    runtime_health_check_passed: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_health_check_passed)
                        .unwrap_or(false),
                    runtime_h_hat: rt_h_hat,
                    runtime_rho_hat: rt_rho_hat,
                    runtime_l_hat: rt_l_hat,
                    runtime_match_score: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_match_score)
                        .unwrap_or(0.0),
                    runtime_w1_distance: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_w1_distance)
                        .unwrap_or(0.0),
                    runtime_w1_threshold: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_w1_threshold)
                        .unwrap_or(0.0),
                    runtime_anchor_prefix: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_anchor_prefix.clone())
                        .unwrap_or_default(),
                    runtime_error: runtime_snapshot
                        .as_ref()
                        .map(|v| v.runtime_error.clone())
                        .unwrap_or_default(),
                    // Derived resonant health metrics (C-DBRW spec §4.5.4, §7, §8.1)
                    runtime_h0_eff: h0_eff,
                    runtime_recommended_n: recommended_n,
                    runtime_resonant_status: resonant_status.to_string(),
                    ..Default::default()
                };

                pack_envelope_ok(generated::envelope::Payload::DbrwStatusResponse(response))
            }
            other => err(format!("unknown dbrw query: {other}")),
        }
    }

    /// Dispatch handler for `ble.command` invoke route.
    pub(crate) async fn handle_ble_invoke(&self, i: AppInvoke) -> AppResult {
        match i.method.as_str() {
            "ble.command" => {
                // Decode ArgPack
                let pack = match generated::ArgPack::decode(&*i.args) {
                    Ok(p) => p,
                    Err(e) => return err(format!("decode ArgPack failed: {e}")),
                };
                if pack.codec != generated::Codec::Proto as i32 {
                    return err("ble.command: ArgPack.codec must be PROTO".into());
                }
                // Decode BleCommand
                let cmd = match generated::BleCommand::decode(&*pack.body) {
                    Ok(c) => c,
                    Err(e) => return err(format!("decode BleCommand failed: {e}")),
                };

                // Dispatch to registered backend
                if let Some(backend) = crate::ble::get_ble_backend() {
                    let resp = backend.handle_command(cmd);
                    // NEW: Return as Envelope.bleCommandResponse (field 48)
                    pack_envelope_ok(generated::envelope::Payload::BleCommandResponse(resp))
                } else {
                    err("no BLE backend registered".into())
                }
            }

            other => err(format!("unknown ble invoke: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn push_u32_be(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    fn push_f32_be(buf: &mut Vec<u8>, value: f32) {
        buf.extend_from_slice(&value.to_bits().to_be_bytes());
    }

    #[test]
    fn compute_resonant_health_classifies_pass() {
        let (status, h0_eff, recommended_n) = compute_resonant_health(0.60, 0.10, 0.55);
        assert_eq!(status, "PASS");
        assert!((h0_eff - 0.54).abs() < 1e-6);
        assert_eq!(recommended_n, 4096);
    }

    #[test]
    fn compute_resonant_health_classifies_resonant() {
        let (status, h0_eff, recommended_n) = compute_resonant_health(0.80, 0.35, 0.60);
        assert_eq!(status, "RESONANT");
        assert!((h0_eff - 0.52).abs() < 1e-6);
        assert_eq!(recommended_n, 4096);
    }

    #[test]
    fn compute_resonant_health_classifies_adapted() {
        let (status, h0_eff, recommended_n) = compute_resonant_health(0.58, 0.40, 0.55);
        assert_eq!(status, "ADAPTED");
        assert!((h0_eff - 0.348).abs() < 1e-6);
        assert_eq!(recommended_n, 16384);
    }

    #[test]
    fn compute_resonant_health_classifies_fail() {
        let (status, h0_eff, recommended_n) = compute_resonant_health(0.30, 0.10, 0.20);
        assert_eq!(status, "FAIL");
        assert!((h0_eff - 0.27).abs() < 1e-6);
        assert_eq!(recommended_n, 16384);
    }

    #[test]
    fn load_cdbrw_enrollment_reads_expected_binary_layout() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(CDBRW_ENROLLMENT_FILE);

        let histogram = [0.25f32, 0.75f32];
        let anchor = vec![0xAB; 32];
        let mut bytes = Vec::new();
        push_u32_be(&mut bytes, 4);
        push_u32_be(&mut bytes, 8 * 1024 * 1024);
        push_u32_be(&mut bytes, 4096);
        push_u32_be(&mut bytes, 4096);
        push_u32_be(&mut bytes, 256);
        push_u32_be(&mut bytes, 7);
        push_f32_be(&mut bytes, 0.125f32);
        push_u32_be(&mut bytes, histogram.len() as u32);
        for value in histogram {
            push_f32_be(&mut bytes, value);
        }
        push_u32_be(&mut bytes, anchor.len() as u32);
        bytes.extend_from_slice(&anchor);

        fs::write(&path, bytes).expect("write enrollment");

        let enrollment = load_cdbrw_enrollment(dir.path())
            .expect("parse ok")
            .expect("enrollment exists");

        assert_eq!(enrollment.revision, 4);
        assert_eq!(enrollment.arena_bytes, 8 * 1024 * 1024);
        assert_eq!(enrollment.probes, 4096);
        assert_eq!(enrollment.steps_per_probe, 4096);
        assert_eq!(enrollment.histogram_bins, 256);
        assert_eq!(enrollment.rotation_bits, 7);
        assert!((enrollment.epsilon_intra - 0.125f32).abs() < f32::EPSILON);
        assert_eq!(enrollment.mean_histogram_len, 2);
        assert_eq!(enrollment.reference_anchor, anchor);
    }
}
