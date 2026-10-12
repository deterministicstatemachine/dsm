// SPDX-License-Identifier: Apache-2.0
//
// Included by every Rust crate's build script. The build fails when the crate's own sources
// hold a line that scripts/real_code_guard.py refuses and its baseline does not already
// record. The guard runs whenever the crate's sources, the guard or its baseline change.

fn real_code_guard() -> Result<(), String> {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|e| format!("real-code guard: CARGO_MANIFEST_DIR: {e}"))?,
    );
    let root = manifest
        .ancestors()
        .find(|dir| dir.join("scripts/real_code_guard.py").is_file())
        .ok_or_else(|| {
            format!(
                "real-code guard: scripts/real_code_guard.py is not above {}",
                manifest.display()
            )
        })?
        .to_path_buf();
    for input in ["src", "tests", "benches", "examples", "build.rs"] {
        let path = manifest.join(input);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        root.join("scripts/real_code_guard.py").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("scripts/real_code_baseline.txt").display()
    );
    let scope = manifest
        .strip_prefix(&root)
        .map_err(|e| format!("real-code guard: the crate is not inside the repository: {e}"))?;
    let status = std::process::Command::new("python3")
        .arg(root.join("scripts/real_code_guard.py"))
        .arg("--root")
        .arg(&root)
        .arg("--scope")
        .arg(scope)
        .status()
        .map_err(|e| format!("real-code guard: python3 could not run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("real-code guard refused this crate's sources: the violations are listed above".to_string())
    }
}
