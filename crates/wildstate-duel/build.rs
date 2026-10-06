// SPDX-License-Identifier: MIT OR Apache-2.0
// The build refuses what scripts/real_code_guard.py forbids in this crate.
include!("../../scripts/real_code_guard_build.rs");

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=tests/vectors/v1/vectors.ccb");
    real_code_guard()
}
