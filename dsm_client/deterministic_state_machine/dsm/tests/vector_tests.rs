use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use dsm::types::proto as gp;
use prost::Message;

const VECTOR_REJECT_PROOF_TOO_LARGE: u32 = 470;
const VECTOR_REJECT_INVALID_PROOF: u32 = 471;
const VECTOR_REJECT_MISSING_WITNESS: u32 = 472;
const VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE: u32 = 473;
const VECTOR_REJECT_STORAGE_ERROR: u32 = 474;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectCode {
    Accept,
    DecodeError,
    ProofTooLarge,
    InvalidProof,
    MissingWitness,
    ModalConflictPendingOnline,
    StorageError,
    UnknownReject,
}

impl RejectCode {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim() {
            "ACCEPT" => RejectCode::Accept,
            "DECODE_ERROR" => RejectCode::DecodeError,
            "PROOF_TOO_LARGE" => RejectCode::ProofTooLarge,
            "INVALID_PROOF" => RejectCode::InvalidProof,
            "MISSING_WITNESS" => RejectCode::MissingWitness,
            "MODAL_CONFLICT_PENDING_ONLINE" => RejectCode::ModalConflictPendingOnline,
            "STORAGE_ERROR" => RejectCode::StorageError,
            "UNKNOWN_REJECT" => RejectCode::UnknownReject,
            other => return Err(anyhow!("unknown RejectCode: {}", other)),
        })
    }
}

fn parse_expected_code(expected_kv: &str) -> Result<RejectCode> {
    for raw in expected_kv.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "code" {
                return RejectCode::parse(v);
            }
        }
    }
    Err(anyhow!("expected.kv missing code=..."))
}

fn discover_cases(root: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Err(anyhow!("vector root missing: {}", root.display()));
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() && p.join("request.bin").exists() && p.join("expected.kv").exists() {
            out.push(p);
        }
    }
    out.sort();
    if out.is_empty() {
        return Err(anyhow!("no cases found in {}", root.display()));
    }
    Ok(out)
}

fn map_reject_from_real_impl(wire: &[u8]) -> RejectCode {
    let resp = dsm::core::bridge::handle_envelope_universal(wire);
    let env = match gp::Envelope::decode(resp.as_slice()) {
        Ok(e) => e,
        Err(_) => return RejectCode::DecodeError,
    };

    if let Some(gp::envelope::Payload::Error(err)) = env.payload {
        return map_reject_code(err.code);
    }

    if let Some(gp::envelope::Payload::UniversalRx(rx)) = env.payload {
        if let Some(result) = rx.results.first() {
            if result.accepted {
                return RejectCode::Accept;
            }
            if let Some(err) = result.error.as_ref() {
                return map_reject_code(err.code);
            }
        }
    }

    RejectCode::UnknownReject
}

fn map_reject_code(code: u32) -> RejectCode {
    match code {
        400 => RejectCode::DecodeError,
        VECTOR_REJECT_PROOF_TOO_LARGE => RejectCode::ProofTooLarge,
        VECTOR_REJECT_INVALID_PROOF => RejectCode::InvalidProof,
        VECTOR_REJECT_MISSING_WITNESS => RejectCode::MissingWitness,
        VECTOR_REJECT_MODAL_CONFLICT_PENDING_ONLINE => RejectCode::ModalConflictPendingOnline,
        VECTOR_REJECT_STORAGE_ERROR => RejectCode::StorageError,
        _ => RejectCode::UnknownReject,
    }
}

#[test]
fn vectors_v1() -> Result<()> {
    let root = PathBuf::from("tests/vectors/v1");
    let cases = discover_cases(&root)?;

    for case_dir in cases {
        let request = fs::read(case_dir.join("request.bin"))?;
        let expected_kv = fs::read_to_string(case_dir.join("expected.kv"))?;
        let expected = parse_expected_code(&expected_kv)?;

        let got = map_reject_from_real_impl(&request);

        if got != expected {
            return Err(anyhow!(
                "vector failed: {} expected={:?} got={:?}",
                case_dir.display(),
                expected,
                got
            ));
        }
    }

    Ok(())
}
