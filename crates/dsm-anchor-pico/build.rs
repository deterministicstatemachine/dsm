//! Put `memory.x` on the linker search path and rebuild when it changes.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

include!("../../scripts/real_code_guard_build.rs");

fn main() {
    if let Err(refusal) = real_code_guard() {
        eprintln!("{refusal}");
        std::process::exit(1);
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
