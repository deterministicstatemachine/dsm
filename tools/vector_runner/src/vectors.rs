use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub code: RejectCode,
    pub debug: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectCode {
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
    pub fn as_str(self) -> &'static str {
        match self {
            RejectCode::Accept => "ACCEPT",
            RejectCode::DecodeError => "DECODE_ERROR",
            RejectCode::ProofTooLarge => "PROOF_TOO_LARGE",
            RejectCode::InvalidProof => "INVALID_PROOF",
            RejectCode::MissingWitness => "MISSING_WITNESS",
            RejectCode::ModalConflictPendingOnline => "MODAL_CONFLICT_PENDING_ONLINE",
            RejectCode::StorageError => "STORAGE_ERROR",
            RejectCode::UnknownReject => "UNKNOWN_REJECT",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "ACCEPT" => Ok(RejectCode::Accept),
            "DECODE_ERROR" => Ok(RejectCode::DecodeError),
            "PROOF_TOO_LARGE" => Ok(RejectCode::ProofTooLarge),
            "INVALID_PROOF" => Ok(RejectCode::InvalidProof),
            "MISSING_WITNESS" => Ok(RejectCode::MissingWitness),
            "MODAL_CONFLICT_PENDING_ONLINE" => Ok(RejectCode::ModalConflictPendingOnline),
            "STORAGE_ERROR" => Ok(RejectCode::StorageError),
            "UNKNOWN_REJECT" => Ok(RejectCode::UnknownReject),
            other => Err(anyhow!("unknown RejectCode: {}", other)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Expected {
    pub code: RejectCode,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub id: String,
    /// Case directory is used in diagnostics (so it is not dead code).
    pub dir: PathBuf,
    pub request_bin: PathBuf,
    pub expected_kv: PathBuf,
}

#[derive(Clone, Debug)]
pub struct CaseResult {
    pub case_id: String,
    pub case_dir: PathBuf,
    pub expected: Reject,
    pub got: Reject,
    pub passed: bool,
}

pub trait VectorApi {
    fn process_wire(&mut self, wire: &[u8], case_id: &str) -> Reject;
}

/// Keep a NoopApi available, but only compile it when explicitly enabled.
/// This avoids dead-code warnings in normal builds.
#[cfg(feature = "noop_api")]
#[allow(dead_code)]
pub struct NoopApi;

#[cfg(feature = "noop_api")]
impl NoopApi {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "noop_api")]
impl VectorApi for NoopApi {
    fn process_wire(&mut self, _wire: &[u8], case_id: &str) -> Reject {
        Reject {
            code: RejectCode::UnknownReject,
            debug: Some(format!(
                "NoopApi active. Implement VectorApi::process_wire. case_id={}",
                case_id
            )),
        }
    }
}

pub struct VectorRunner {
    root: PathBuf,
}

impl VectorRunner {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn run_all<A: VectorApi>(&mut self, api: &mut A) -> Result<Vec<CaseResult>> {
        let cases = discover_cases(&self.root)?;
        let mut out = Vec::with_capacity(cases.len());

        for c in cases {
            let wire = fs::read(&c.request_bin)
                .with_context(|| format!("read request.bin: {}", c.request_bin.display()))?;
            let expected = parse_expected_kv(&c.expected_kv)
                .with_context(|| format!("parse expected.kv: {}", c.expected_kv.display()))?;

            let got = api.process_wire(&wire, &c.id);

            let exp_reject = Reject {
                code: expected.code,
                debug: None,
            };

            let passed = got.code == exp_reject.code;

            out.push(CaseResult {
                case_id: c.id,
                case_dir: c.dir.clone(),
                expected: exp_reject,
                got,
                passed,
            });
        }

        out.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        Ok(out)
    }
}

fn discover_cases(root: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_dir() {
            continue;
        }

        let dir = entry.path();
        if dir == root {
            continue;
        }

        let request_bin = dir.join("request.bin");
        let expected_kv = dir.join("expected.kv");

        if request_bin.exists() && expected_kv.exists() {
            let id = dir
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow!("non-utf8 case dir name: {}", dir.display()))?
                .to_string();

            cases.push(Case {
                id,
                dir: dir.to_path_buf(),
                request_bin,
                expected_kv,
            });
        }
    }

    if cases.is_empty() {
        return Err(anyhow!(
            "no cases found under {} (expected directories with request.bin + expected.kv)",
            root.display()
        ));
    }

    Ok(cases)
}

fn parse_expected_kv(path: &Path) -> Result<Expected> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let map = parse_kv(&text)?;

    let code_s = map
        .get("code")
        .ok_or_else(|| anyhow!("expected.kv missing key: code"))?;

    Ok(Expected {
        code: RejectCode::parse(code_s)?,
    })
}

fn parse_kv(text: &str) -> Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(anyhow!("invalid kv line {}: {}", i + 1, raw));
        };
        let key = k.trim().to_string();
        let val = v.trim().to_string();
        if key.is_empty() {
            return Err(anyhow!("empty key on line {}", i + 1));
        }
        m.insert(key, val);
    }

    Ok(m)
}
