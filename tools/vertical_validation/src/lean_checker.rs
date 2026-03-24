//! Lean 4 proof checker.
//!
//! Discovers all `.lean` files under `lean4/`, type-checks each one,
//! and extracts theorem/axiom counts for formal verification reports.

use instant::Instant;
use serde::Serialize;
use std::path::Path;

/// Result of checking a single Lean 4 proof file.
#[derive(Debug, Clone, Serialize)]
pub struct LeanProofResult {
    /// Filename (e.g., "DSMOfflineFinality.lean")
    pub file: String,
    /// Whether the file type-checked successfully
    pub passed: bool,
    /// Theorem names extracted from source
    pub theorems: Vec<String>,
    /// Axiom names extracted from source
    pub axioms: Vec<String>,
    /// Whether the file contains any `sorry` (incomplete proof)
    pub has_sorry: bool,
    /// Runtime in milliseconds
    pub duration_ms: f64,
    /// Errors (empty if passed)
    pub errors: Vec<String>,
}

/// Aggregated results for all Lean 4 proof files.
#[derive(Debug, Clone, Serialize)]
pub struct LeanSuiteResult {
    /// Per-file results
    pub results: Vec<LeanProofResult>,
    /// Whether all files passed
    pub all_passed: bool,
    /// Total runtime in milliseconds
    pub duration_ms: f64,
    /// Lean 4 version string (from `lean --version`)
    pub lean_version: String,
}

/// Run the Lean 4 type checker on all `.lean` files under `{project_root}/lean4/`.
pub fn collect_lean_results(project_root: &Path) -> LeanSuiteResult {
    eprintln!("\n=== LEAN 4 PROOF CHECKING ===\n");
    let suite_start = Instant::now();

    let lean_version = get_lean_version();
    eprintln!("  Lean version: {lean_version}");

    let lean_dir = project_root.join("lean4");
    let mut results = Vec::new();

    if !lean_dir.exists() {
        eprintln!("  lean4/ directory not found — skipping");
        return LeanSuiteResult {
            results,
            all_passed: true,
            duration_ms: suite_start.elapsed().as_secs_f64() * 1000.0,
            lean_version,
        };
    }

    // Discover .lean files (sorted for deterministic ordering)
    let read_dir = match std::fs::read_dir(&lean_dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("  failed to read lean4/: {e}");
            return LeanSuiteResult {
                results,
                all_passed: false,
                duration_ms: suite_start.elapsed().as_secs_f64() * 1000.0,
                lean_version,
            };
        }
    };
    let mut lean_files: Vec<_> = read_dir
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("lean") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    lean_files.sort();

    eprintln!("  Found {} .lean files\n", lean_files.len());

    for (idx, path) in lean_files.iter().enumerate() {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let start = Instant::now();

        // Parse source for theorem/axiom names and sorry
        let source = std::fs::read_to_string(path).unwrap_or_default();
        let theorems = extract_declarations(&source, "theorem");
        let axioms = extract_declarations(&source, "axiom");
        let has_sorry = source.contains("sorry");

        // Run `lean <file>` and capture result
        let output = std::process::Command::new("lean").arg(path).output();

        let (passed, errors) = match output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                if out.status.success() {
                    // Filter out warnings — only real errors count as failures
                    let real_errors: Vec<String> = stderr
                        .lines()
                        .filter(|l| l.contains("error"))
                        .map(String::from)
                        .collect();
                    (real_errors.is_empty(), real_errors)
                } else {
                    let error_lines: Vec<String> = stderr
                        .lines()
                        .filter(|l| !l.is_empty())
                        .map(String::from)
                        .collect();
                    (false, error_lines)
                }
            }
            Err(e) => (false, vec![format!("failed to execute lean: {e}")]),
        };

        let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
        let icon = if passed { "PASS" } else { "FAIL" };
        let sorry_tag = if has_sorry { " [sorry!]" } else { "" };
        eprintln!(
            "  [{}/{}] {} -> {} ({} theorems, {} axioms{}) {:.1}ms",
            idx + 1,
            lean_files.len(),
            file_name,
            icon,
            theorems.len(),
            axioms.len(),
            sorry_tag,
            duration_ms,
        );

        results.push(LeanProofResult {
            file: file_name,
            passed,
            theorems,
            axioms,
            has_sorry,
            duration_ms,
            errors,
        });
    }

    let all_passed = results.iter().all(|r| r.passed);
    let duration_ms = suite_start.elapsed().as_secs_f64() * 1000.0;

    LeanSuiteResult {
        results,
        all_passed,
        duration_ms,
        lean_version,
    }
}

/// Extract declaration names matching `keyword <name>` from Lean source.
fn extract_declarations(source: &str, keyword: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        // Match lines like: `theorem foo_bar`, `axiom baz_qux`
        // Also handles: `theorem foo_bar (args...)` and `private theorem ...`
        let search_line = if trimmed.starts_with("private ") || trimmed.starts_with("protected ") {
            // Skip visibility modifier
            trimmed.splitn(2, ' ').nth(1).unwrap_or("")
        } else {
            trimmed
        };

        if let Some(rest) = search_line.strip_prefix(keyword) {
            if let Some(first_char) = rest.chars().next() {
                if first_char == ' ' {
                    // Extract the name (first word after keyword)
                    if let Some(name) = rest.trim().split_whitespace().next() {
                        // Skip if it's a keyword continuation (e.g., "theorem" in a comment)
                        if !name.is_empty()
                            && name
                                .chars()
                                .next()
                                .map_or(false, |c| c.is_alphabetic() || c == '_')
                        {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }
    }
    names
}

/// Get Lean 4 version string.
fn get_lean_version() -> String {
    match std::process::Command::new("lean").arg("--version").output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.trim().to_string()
        }
        Err(_) => "lean not found".to_string(),
    }
}
