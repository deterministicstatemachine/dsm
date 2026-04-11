// SPDX-License-Identifier: MIT OR Apache-2.0
//! Miscellaneous route handlers for AppRouterImpl.
//!
//! Handles `debug.*` query routes, the `dbrw.status` + `cdbrw.*` query
//! surface (C-DBRW Protocol 6.2 Algorithm 3 and the enrollment writer),
//! and the `ble.command` invoke route.
//!
//! ## C-DBRW single path
//!
//! Every C-DBRW operation — probe, respond, verify, enroll, measure trust —
//! flows through this module. Kotlin is transport-only: it supplies raw
//! orbit timings via protobuf args and never sees keys, histograms, or
//! ciphertexts. There is no reverse JNI call from Rust to Kotlin in this
//! file. `dbrw.status` and `cdbrw.measure_trust` read the live verdict from
//! [`crate::security::cdbrw_access_gate::latest_trust`]; Kotlin never holds
//! a binary runtime snapshot — that legacy path is gone.

use dsm::types::proto as generated;
use prost::Message;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use crate::bridge::{AppInvoke, AppQuery, AppResult};
use crate::security::cdbrw_access_gate::{latest_trust, TrustSnapshot};
use crate::security::cdbrw_enrollment_writer::{enroll_device, EnrollError, EnrollInputs};
use crate::security::cdbrw_responder::{
    measure_trust, respond_to_challenge, RespondError, RespondInputs,
};
use crate::security::cdbrw_verifier::{
    read_verifier_public_key_if_present, verify_challenge_response, CdbrwVerificationRequest,
};
use super::app_router_impl::AppRouterImpl;
use super::response_helpers::{err, pack_bytes_ok, pack_envelope_ok};

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
    mean_histogram: Vec<f32>,
    reference_anchor: Vec<u8>,
}

impl DbrwEnrollmentSnapshot {
    fn mean_histogram_len(&self) -> u32 {
        self.mean_histogram.len() as u32
    }
}

fn take_prefix(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(PREFIX_BYTES).collect()
}

/// Empty proto trust snapshot used when the access gate has never been
/// updated (e.g. fresh process, no enrollment). Callers rely on the
/// `access_level == CDBRW_ACCESS_UNSPECIFIED` sentinel to distinguish
/// "never run" from an intentional "Blocked" verdict.
fn empty_trust_proto() -> generated::CdbrwTrustSnapshot {
    generated::CdbrwTrustSnapshot {
        access_level: generated::CdbrwAccessLevel::CdbrwAccessUnspecified as i32,
        resonant_status: generated::CdbrwResonantStatus::CdbrwResonantUnspecified as i32,
        h_hat: 0.0,
        rho_hat: 0.0,
        l_hat: 0.0,
        h0_eff: 0.0,
        trust_score: 0.0,
        iter: 0,
        recommended_n: 0,
        w1_distance: 0.0,
        w1_threshold: 0.0,
        note: String::new(),
    }
}

/// Convert an optional [`TrustSnapshot`] into its proto form. `None` becomes
/// the empty sentinel so downstream consumers see a consistent shape.
fn trust_proto(snapshot: Option<TrustSnapshot>, note: &str) -> generated::CdbrwTrustSnapshot {
    match snapshot {
        Some(s) => s.to_proto(note),
        None => empty_trust_proto(),
    }
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

    // Decode the stored histogram back into f32 so the in-memory snapshot
    // can feed the measure_trust / respond paths. The on-disk format uses
    // BIG-ENDIAN f32 (written via Java DataOutputStream.writeFloat which
    // defaults to BE) — this is deliberately distinct from the LE form
    // embedded in the anchor preimage.
    let mut mean_histogram = Vec::with_capacity(mean_histogram_len as usize);
    for i in 0..mean_histogram_len as usize {
        let start = i * 4;
        let bytes = [
            scratch[start],
            scratch[start + 1],
            scratch[start + 2],
            scratch[start + 3],
        ];
        mean_histogram.push(f32::from_bits(u32::from_be_bytes(bytes)));
    }

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
        mean_histogram,
        reference_anchor,
    }))
}

/// Convert a length-32 slice into a fixed-size array. Returns an error with
/// the given field name if the slice is the wrong size.
fn slice_to_array32(bytes: &[u8], field: &str) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("{field} must be 32 bytes (got {})", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
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

    /// Dispatch handler for `dbrw.status` and `cdbrw.*` query routes.
    ///
    /// All C-DBRW operations flow through this single entry point. The router
    /// layer already decoded the ArgPack; we re-decode the inner protobuf,
    /// dispatch to the Rust-side implementation, and wrap the result back into
    /// an envelope payload.
    pub(crate) async fn handle_dbrw_query(&self, q: AppQuery) -> AppResult {
        dispatch_dbrw_query(q).await
    }
}

pub(crate) async fn dispatch_dbrw_query(q: AppQuery) -> AppResult {
        match q.path.as_str() {
            // -------- dbrw.status --------
            "dbrw.status" => {
                let storage_base_dir = crate::storage_utils::get_storage_base_dir();
                let binding_key = crate::binding_key::get_binding_key();
                let verifier_public_key = read_verifier_public_key_if_present()
                    .ok()
                    .flatten()
                    .unwrap_or_default();

                let mut status_note = String::new();

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

                if status_note.is_empty() {
                    status_note = if enrollment.is_some() {
                        "Enrollment loaded from disk.".to_string()
                    } else {
                        "Device not yet enrolled.".to_string()
                    };
                }

                let trust = trust_proto(latest_trust(), "dbrw.status");

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
                        .map(|v| v.mean_histogram_len())
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
                    trust: Some(trust),
                };

                pack_envelope_ok(generated::envelope::Payload::DbrwStatusResponse(response))
            }

            // -------- cdbrw.measure_trust --------
            "cdbrw.measure_trust" => {
                let req = match generated::CdbrwMeasureTrustRequest::decode(&*q.params) {
                    Ok(v) => v,
                    Err(e) => return err(format!("decode CdbrwMeasureTrustRequest failed: {e}")),
                };
                let orbit = match req.orbit.as_ref() {
                    Some(v) => v,
                    None => return err("cdbrw.measure_trust: missing orbit".into()),
                };

                let (enrolled_mean_owned, epsilon_intra) =
                    match crate::storage_utils::get_storage_base_dir()
                        .as_ref()
                        .and_then(|dir| load_cdbrw_enrollment(dir).ok().flatten())
                    {
                        Some(snapshot) => (Some(snapshot.mean_histogram.clone()), snapshot.epsilon_intra),
                        None => (None, 0.0f32),
                    };

                let snapshot = measure_trust(
                    &orbit.timings,
                    enrolled_mean_owned.as_deref(),
                    epsilon_intra,
                    req.histogram_bins as usize,
                );

                pack_envelope_ok(generated::envelope::Payload::CdbrwTrustSnapshot(
                    snapshot.to_proto("cdbrw.measure_trust"),
                ))
            }

            // -------- cdbrw.respond --------
            "cdbrw.respond" => {
                let req = match generated::CdbrwRespondRequest::decode(&*q.params) {
                    Ok(v) => v,
                    Err(e) => return err(format!("decode CdbrwRespondRequest failed: {e}")),
                };

                let orbit = match req.orbit.as_ref() {
                    Some(v) => v,
                    None => return err("cdbrw.respond: missing orbit".into()),
                };

                let challenge = match slice_to_array32(&req.challenge, "challenge") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let chain_tip = match slice_to_array32(&req.chain_tip, "chain_tip") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let commitment_preimage =
                    match slice_to_array32(&req.commitment_preimage, "commitment_preimage") {
                        Ok(v) => v,
                        Err(e) => return err(e),
                    };
                let device_id = match slice_to_array32(&req.device_id, "device_id") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };

                let binding_key_vec = match crate::binding_key::get_binding_key() {
                    Some(k) => k,
                    None => {
                        return err(
                            "cdbrw.respond: binding key not set (bootstrap incomplete)".into(),
                        )
                    }
                };
                let binding_key = match slice_to_array32(&binding_key_vec, "binding_key") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };

                let (enrolled_mean_owned, epsilon_intra) =
                    match crate::storage_utils::get_storage_base_dir()
                        .as_ref()
                        .and_then(|dir| load_cdbrw_enrollment(dir).ok().flatten())
                    {
                        Some(snapshot) => (Some(snapshot.mean_histogram.clone()), snapshot.epsilon_intra),
                        None => (None, 0.0f32),
                    };

                let inputs = RespondInputs {
                    orbit_timings: &orbit.timings,
                    enrolled_mean: enrolled_mean_owned.as_deref(),
                    epsilon_intra,
                    verifier_public_key: &req.verifier_public_key,
                    challenge: &challenge,
                    chain_tip: &chain_tip,
                    commitment_preimage: &commitment_preimage,
                    device_id: &device_id,
                    binding_key: &binding_key,
                    histogram_bins: req.histogram_bins as usize,
                };

                match respond_to_challenge(&inputs) {
                    Ok(out) => {
                        let resp = generated::CdbrwRespondResponse {
                            ciphertext: out.ciphertext,
                            gamma: out.gamma.to_vec(),
                            signature: out.signature,
                            ephemeral_public_key: out.ephemeral_public_key,
                            trust: Some(out.trust.to_proto("cdbrw.respond")),
                        };
                        pack_envelope_ok(generated::envelope::Payload::CdbrwRespondResponse(resp))
                    }
                    Err(RespondError::EntropyHealthFailed(h)) => err(format!(
                        "cdbrw.respond: entropy health FAIL (H={:.4} |rho|={:.4} L={:.4})",
                        h.h_hat,
                        h.rho_hat.abs(),
                        h.l_hat
                    )),
                    Err(e) => err(format!("cdbrw.respond: {e}")),
                }
            }

            // -------- cdbrw.verify --------
            "cdbrw.verify" => {
                let req = match generated::CdbrwVerifyRequest::decode(&*q.params) {
                    Ok(v) => v,
                    Err(e) => return err(format!("decode CdbrwVerifyRequest failed: {e}")),
                };

                let challenge = match slice_to_array32(&req.challenge, "challenge") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let gamma = match slice_to_array32(&req.gamma, "gamma") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let chain_tip = match slice_to_array32(&req.chain_tip, "chain_tip") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };
                let commitment_preimage =
                    match slice_to_array32(&req.commitment_preimage, "commitment_preimage") {
                        Ok(v) => v,
                        Err(e) => return err(e),
                    };
                let enrollment_anchor =
                    match slice_to_array32(&req.enrollment_anchor, "enrollment_anchor") {
                        Ok(v) => v,
                        Err(e) => return err(e),
                    };

                let binding_key_vec = match crate::binding_key::get_binding_key() {
                    Some(k) => k,
                    None => {
                        return err(
                            "cdbrw.verify: binding key not set (bootstrap incomplete)".into(),
                        )
                    }
                };
                let binding_key = match slice_to_array32(&binding_key_vec, "binding_key") {
                    Ok(v) => v,
                    Err(e) => return err(e),
                };

                let verification_request = CdbrwVerificationRequest {
                    binding_key: &binding_key,
                    challenge: &challenge,
                    gamma: &gamma,
                    ciphertext: &req.ciphertext,
                    signature: &req.signature,
                    supplied_ephemeral_public_key: &req.ephemeral_public_key,
                    chain_tip: &chain_tip,
                    commitment_preimage: &commitment_preimage,
                    enrollment_anchor: &enrollment_anchor,
                    epsilon_intra: req.epsilon_intra,
                    epsilon_inter: req.epsilon_inter,
                };

                match verify_challenge_response(&verification_request) {
                    Ok(outcome) => {
                        let resp = generated::CdbrwVerifyResponse {
                            accepted: outcome.accepted,
                            reason: outcome.reason.to_string(),
                            gamma_distance: outcome.gamma_distance,
                            threshold: outcome.threshold,
                        };
                        pack_envelope_ok(generated::envelope::Payload::CdbrwVerifyResponse(resp))
                    }
                    Err(e) => err(format!("cdbrw.verify: {e}")),
                }
            }

            // -------- cdbrw.enroll --------
            "cdbrw.enroll" => {
                let req = match generated::CdbrwEnrollRequest::decode(&*q.params) {
                    Ok(v) => v,
                    Err(e) => return err(format!("decode CdbrwEnrollRequest failed: {e}")),
                };

                // Convert trials from repeated CdbrwOrbitTrial to Vec<Vec<i64>>.
                // Empty trials get caught by the writer's validation.
                let trials: Vec<Vec<i64>> =
                    req.trials.into_iter().map(|t| t.timings).collect();

                let inputs = EnrollInputs {
                    env_bytes: &req.env_bytes,
                    trials: &trials,
                    arena_bytes: req.arena_bytes,
                    probes: req.probes,
                    steps_per_probe: req.steps_per_probe,
                    histogram_bins: req.histogram_bins,
                    rotation_bits: req.rotation_bits,
                };

                let base_dir = match crate::storage_utils::get_storage_base_dir() {
                    Some(d) => d,
                    None => {
                        return err(
                            "cdbrw.enroll: storage base directory not initialized".into(),
                        )
                    }
                };

                match enroll_device(&base_dir, &inputs) {
                    Ok(out) => {
                        let resp = generated::CdbrwEnrollResponse {
                            revision: out.revision,
                            epsilon_intra: out.epsilon_intra,
                            mean_histogram_len: out.mean_histogram_len,
                            reference_anchor_prefix: out.reference_anchor_prefix,
                            trust: Some(out.trust.to_proto("cdbrw.enroll")),
                            reference_anchor: out.reference_anchor.to_vec(),
                        };
                        pack_envelope_ok(generated::envelope::Payload::CdbrwEnrollResponse(resp))
                    }
                    Err(EnrollError::InsufficientTrials { got }) => err(format!(
                        "cdbrw.enroll: insufficient trials (got {got}, need >= 16)"
                    )),
                    Err(EnrollError::EmptyTrial { index }) => {
                        err(format!("cdbrw.enroll: trial {index} has no timings"))
                    }
                    Err(EnrollError::InvalidHistogramBins { bins }) => err(format!(
                        "cdbrw.enroll: invalid histogram_bins={bins} (expected 256/512/1024)"
                    )),
                    Err(EnrollError::Io(msg)) => err(format!("cdbrw.enroll: io error: {msg}")),
                }
            }

            other => err(format!("unknown dbrw query: {other}")),
        }
    }

impl AppRouterImpl {

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
        assert_eq!(enrollment.mean_histogram_len(), 2);
        assert!((enrollment.mean_histogram[0] - 0.25f32).abs() < f32::EPSILON);
        assert!((enrollment.mean_histogram[1] - 0.75f32).abs() < f32::EPSILON);
        assert_eq!(enrollment.reference_anchor, anchor);
    }

    #[test]
    fn slice_to_array32_accepts_exact_length() {
        let data = [7u8; 32];
        let arr = slice_to_array32(&data, "test").expect("conversion");
        assert_eq!(arr, data);
    }

    #[test]
    fn slice_to_array32_rejects_wrong_length() {
        assert!(slice_to_array32(&[0u8; 31], "test").is_err());
        assert!(slice_to_array32(&[0u8; 33], "test").is_err());
    }

    #[test]
    fn empty_trust_proto_is_unspecified() {
        let p = empty_trust_proto();
        assert_eq!(
            p.access_level,
            generated::CdbrwAccessLevel::CdbrwAccessUnspecified as i32
        );
        assert_eq!(
            p.resonant_status,
            generated::CdbrwResonantStatus::CdbrwResonantUnspecified as i32
        );
        assert_eq!(p.iter, 0);
    }
}
