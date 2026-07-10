// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stamp the harness's own git commit (+ dirty flag) into the binary so every bench run logs the
//! exact harness build it came from. Rebuild `--release` before a run so this is current.
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    println!("cargo:rustc-env=HARNESS_GIT_COMMIT={commit}");
    println!(
        "cargo:rustc-env=HARNESS_GIT_DIRTY={}",
        if dirty { "-dirty" } else { "" }
    );
    // Re-stamp when a commit lands. `git commit` moves the branch REF, not `.git/HEAD`, so watch the
    // reflog (`.git/logs/HEAD`, appended on every commit/checkout) plus HEAD for branch switches.
    // Workspace `.git` is two levels up from this crate.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");
    // Also re-stamp (updating the -dirty flag) when the source itself is edited.
    println!("cargo:rerun-if-changed=src/main.rs");
}
