//! TLAPS proof runner.
//!
//! Runs machine-checked TLA+ proof modules via `tlapm` and parses theorem-level
//! results for the vertical-validation report.

use std::env;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::bail;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProofSpec {
    pub label: String,
    pub module_file: String,
    pub theorem_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct ProofResult {
    pub passed: bool,
    pub obligations_proved: u64,
    pub duration_ms: f64,
    pub errors: Vec<String>,
    #[serde(skip)]
    #[allow(dead_code)]
    pub raw_stdout: String,
    #[serde(skip)]
    #[allow(dead_code)]
    pub raw_stderr: String,
}

#[derive(Debug, Clone)]
enum TlapmCommand {
    Direct(String),
    OpamFallback,
}

pub struct ProofRunner {
    tla_dir: PathBuf,
    tlapm: TlapmCommand,
}

impl ProofRunner {
    pub fn new(project_root: &Path) -> anyhow::Result<Self> {
        let tla_dir = project_root.join("tla");
        if !tla_dir.join("DSM_Abstract.tla").exists() {
            bail!("DSM_Abstract.tla not found in {}", tla_dir.display());
        }
        let tlapm = resolve_tlapm_command()?;
        Ok(Self { tla_dir, tlapm })
    }

    pub fn standard_specs() -> Vec<ProofSpec> {
        vec![
            ProofSpec {
                label: "DSM_Abstract".into(),
                module_file: "DSM_Abstract.tla".into(),
                theorem_names: vec![
                    "AbstractInit".into(),
                    "AbstractStep".into(),
                    "AbstractSafetyTheorem".into(),
                    "AbstractSpentMonotone".into(),
                    "AbstractCommitMonotone".into(),
                ],
            },
            ProofSpec {
                label: "DSM_ProtocolCore".into(),
                module_file: "DSM_ProtocolCore.tla".into(),
                theorem_names: vec![
                    "CoreInit".into(),
                    "CoreStep".into(),
                    "CoreSafety".into(),
                    "CoreImplementsAbstract".into(),
                ],
            },
            ProofSpec {
                label: "DSM_InitProof".into(),
                module_file: "DSM_InitProof.tla".into(),
                theorem_names: vec!["ConcreteInitRefinesCore".into()],
            },
            // --- Offline Finality (Paper Theorems 4.1, 4.2) ---
            ProofSpec {
                label: "DSM_OfflineFinality".into(),
                module_file: "DSM_OfflineFinality.tla".into(),
                theorem_names: vec![
                    "OfflineFinalityInit".into(),
                    "OfflineFinalityStep".into(),
                    "IrreversibilityInductive".into(),
                    "NoHalfCommitInductive".into(),
                ],
            },
            // --- Non-Interference (Paper Lemma 3.1, Theorem 3.1) ---
            ProofSpec {
                label: "DSM_NonInterference".into(),
                module_file: "DSM_NonInterference.tla".into(),
                theorem_names: vec!["NonInterferenceStep".into()],
            },
        ]
    }

    pub async fn run_spec(&self, spec: &ProofSpec) -> anyhow::Result<ProofResult> {
        let module_path = self.tla_dir.join(&spec.module_file);
        if !module_path.exists() {
            bail!("Proof module not found: {}", module_path.display());
        }

        let started = Instant::now();
        let output = match &self.tlapm {
            TlapmCommand::Direct(cmd) => {
                let future = tokio::process::Command::new(cmd)
                    .arg("--cleanfp")
                    .arg("--stretch")
                    .arg("5")
                    .arg(&spec.module_file)
                    .current_dir(&self.tla_dir)
                    .output();
                match tokio::time::timeout(std::time::Duration::from_secs(120), future).await {
                    Ok(Ok(output)) => output,
                    Ok(Err(error)) => {
                        return Ok(failed_result(
                            duration_ms(started),
                            format!("Failed to execute {} for {}: {}", cmd, spec.label, error),
                        ));
                    }
                    Err(_) => {
                        return Ok(failed_result(
                            duration_ms(started),
                            format!("TLAPS timed out for {}", spec.label),
                        ));
                    }
                }
            }
            TlapmCommand::OpamFallback => {
                let future = tokio::process::Command::new("opam")
                    .arg("exec")
                    .arg("--switch=5.1.0")
                    .arg("--")
                    .arg("tlapm")
                    .arg("--cleanfp")
                    .arg("--stretch")
                    .arg("5")
                    .arg(&spec.module_file)
                    .current_dir(&self.tla_dir)
                    .output();
                match tokio::time::timeout(std::time::Duration::from_secs(120), future).await {
                    Ok(Ok(output)) => output,
                    Ok(Err(error)) => {
                        return Ok(failed_result(
                            duration_ms(started),
                            format!(
                                "Failed to execute tlapm via opam for {}: {}",
                                spec.label, error
                            ),
                        ));
                    }
                    Err(_) => {
                        return Ok(failed_result(
                            duration_ms(started),
                            format!("TLAPS timed out for {}", spec.label),
                        ));
                    }
                }
            }
        };

        let duration_ms = duration_ms(started);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok(parse_tlapm_output(
            output.status.success(),
            duration_ms,
            &stdout,
            &stderr,
        ))
    }

    pub async fn run_all(&self) -> anyhow::Result<Vec<(ProofSpec, ProofResult)>> {
        let mut results = Vec::new();
        for spec in Self::standard_specs() {
            eprintln!("  Running TLAPS: {} ({}) ...", spec.label, spec.module_file);
            let result = self.run_spec(&spec).await?;
            let verdict = if result.passed { "PASSED" } else { "FAILED" };
            eprintln!(
                "    {} ({} obligations, {:.0}ms)",
                verdict, result.obligations_proved, result.duration_ms
            );
            results.push((spec, result));
        }
        Ok(results)
    }
}

fn duration_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn failed_result(duration_ms: f64, error: String) -> ProofResult {
    ProofResult {
        passed: false,
        obligations_proved: 0,
        duration_ms,
        errors: vec![error],
        raw_stdout: String::new(),
        raw_stderr: String::new(),
    }
}

fn resolve_tlapm_command() -> anyhow::Result<TlapmCommand> {
    if let Ok(path) = env::var("DSM_TLAPM_BIN") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(TlapmCommand::Direct(trimmed.to_string()));
        }
    }

    if let Ok(output) = std::process::Command::new("tlapm").arg("--help").output() {
        if output.status.success() {
            return Ok(TlapmCommand::Direct("tlapm".into()));
        }
    }

    if let Ok(output) = std::process::Command::new("opam")
        .arg("exec")
        .arg("--switch=5.1.0")
        .arg("--")
        .arg("tlapm")
        .arg("--help")
        .output()
    {
        if output.status.success() {
            return Ok(TlapmCommand::OpamFallback);
        }
    }

    bail!(
        "Unable to resolve tlapm. Set DSM_TLAPM_BIN, put tlapm on PATH, or install the opam switch."
    );
}

fn parse_tlapm_output(
    command_succeeded: bool,
    duration_ms: f64,
    stdout: &str,
    stderr: &str,
) -> ProofResult {
    let obligation_regex = match Regex::new(r"All\s+(\d+)\s+obligation(?:s)?\s+proved\.") {
        Ok(r) => r,
        Err(_) => {
            return ProofResult {
                passed: false,
                obligations_proved: 0,
                duration_ms,
                errors: vec!["internal: obligation regex failed to compile".to_string()],
                raw_stdout: stdout.to_string(),
                raw_stderr: stderr.to_string(),
            };
        }
    };

    let combined = if stderr.is_empty() {
        stdout.to_string()
    } else if stdout.is_empty() {
        stderr.to_string()
    } else {
        format!("{stdout}\n{stderr}")
    };

    let obligations_proved = obligation_regex
        .captures_iter(&combined)
        .filter_map(|captures| captures.get(1).and_then(|m| m.as_str().parse::<u64>().ok()))
        .last()
        .unwrap_or(0);

    let mut errors: Vec<String> = combined
        .lines()
        .filter(|line| line.contains("[ERROR]:") || line.contains("tlapm ending abnormally"))
        .map(|line| line.trim().to_string())
        .collect();

    if !command_succeeded && errors.is_empty() {
        errors.push("TLAPS exited unsuccessfully without structured error output".into());
    }

    let passed = command_succeeded && errors.is_empty();

    ProofResult {
        passed,
        obligations_proved,
        duration_ms,
        errors,
        raw_stdout: stdout.to_string(),
        raw_stderr: stderr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{failed_result, parse_tlapm_output};

    #[test]
    fn parse_success_with_obligation_count() {
        let result = parse_tlapm_output(
            true,
            12.0,
            "File \"./Foo.tla\":\n[INFO]: All 37 obligations proved.\n",
            "",
        );
        assert!(result.passed);
        assert_eq!(result.obligations_proved, 37);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn parse_failure_with_structured_error() {
        let result = parse_tlapm_output(
            false,
            12.0,
            "File \"./Foo.tla\":\n[ERROR]: Could not prove or check:\n",
            "",
        );
        assert!(!result.passed);
        assert_eq!(result.obligations_proved, 0);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn parse_failure_without_structured_error() {
        let result = parse_tlapm_output(false, 12.0, "", "some backend failure");
        assert!(!result.passed);
        assert_eq!(result.obligations_proved, 0);
        assert_eq!(
            result.errors,
            vec!["TLAPS exited unsuccessfully without structured error output"]
        );
    }

    #[test]
    fn parse_uses_last_obligation_count() {
        let result = parse_tlapm_output(
            true,
            12.0,
            "[INFO]: All 3 obligations proved.\n[INFO]: All 11 obligations proved.\n",
            "",
        );
        assert!(result.passed);
        assert_eq!(result.obligations_proved, 11);
    }

    #[test]
    fn failed_result_marks_run_failed() {
        let result = failed_result(25.0, "timed out".into());
        assert!(!result.passed);
        assert_eq!(result.obligations_proved, 0);
        assert_eq!(result.errors, vec!["timed out"]);
    }
}
