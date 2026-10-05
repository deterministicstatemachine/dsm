// SPDX-License-Identifier: MIT OR Apache-2.0

include!("../../scripts/real_code_guard_build.rs");

fn main() {
    if let Err(refusal) = real_code_guard() {
        eprintln!("{refusal}");
        std::process::exit(1);
    }
}
