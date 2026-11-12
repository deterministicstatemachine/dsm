// SPDX-License-Identifier: MIT OR Apache-2.0
// The build refuses what scripts/real_code_guard.py forbids in this crate.
include!("../../scripts/real_code_guard_build.rs");

use std::path::PathBuf;

fn main() -> Result<(), String> {
    // cortex-m-rt's link.x includes memory.x: put this crate's where the linker looks.
    let out = PathBuf::from(std::env::var("OUT_DIR").map_err(|e| e.to_string())?);
    std::fs::copy("memory.x", out.join("memory.x")).map_err(|e| format!("memory.x: {e}"))?;
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    real_code_guard()
}
