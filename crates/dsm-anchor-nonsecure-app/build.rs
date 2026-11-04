// SPDX-License-Identifier: MIT OR Apache-2.0
// The build refuses what scripts/real_code_guard.py forbids in this crate.
include!("../../scripts/real_code_guard_build.rs");

fn main() -> Result<(), String> {
    // The image is linked by these scripts (`.cargo/config.toml`): a change to
    // either links it again, or the monitor would embed an image laid out by
    // the scripts before.
    println!("cargo:rerun-if-changed=dsm-ns-sram.x");
    println!("cargo:rerun-if-changed=memory.x");
    real_code_guard()
}
