// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compile the reviewed ARMv8-M assembly NSC Secure Gateway veneer and link it into the monitor.
//!
//! The veneer (`veneer/dsm_sg_veneer.S`) defines `dsm_secure_dispatch` directly in `.gnu.sgstubs`
//! (placed in the NSC region by `memory.x`), starting with the `sg` instruction and tail-calling the
//! private Secure Rust handler `dsm_secure_handler`. No `--cmse-implib` is needed — the Non-secure
//! app resolves `dsm_secure_dispatch` at the fixed NSC region base.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=veneer/dsm_sg_veneer.S");
    println!("cargo:rerun-if-changed=veneer/dsm_sg_abi.h");
    println!("cargo:rerun-if-changed=memory.x");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out.join("dsm_sg_veneer.o");
    let lib = out.join("libdsm_sg_veneer.a");

    // Assemble the veneer with clang (LLVM) for the Secure image's ARMv8-M target.
    let status = Command::new("clang")
        .args([
            "--target=arm-none-eabi",
            "-mcpu=cortex-m33",
            "-mfloat-abi=hard",
            "-mfpu=fpv5-sp-d16",
            "-c",
            "veneer/dsm_sg_veneer.S",
            "-o",
        ])
        .arg(&obj)
        .status()
        .expect("clang assemble veneer");
    assert!(status.success(), "veneer assembly failed");

    // Archive it and link it into the monitor.
    let _ = std::fs::remove_file(&lib);
    let ar = Command::new("arm-none-eabi-ar")
        .arg("crs")
        .arg(&lib)
        .arg(&obj)
        .status()
        .expect("ar");
    assert!(ar.success(), "ar failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=dsm_sg_veneer");
    println!("cargo:rustc-link-search={}", env::current_dir().unwrap().display());
    // The monitor does not CALL the gateway (the separate Non-secure app image does), so force the
    // veneer (and, transitively, the Secure handler it references) to be linked + kept, and export
    // the NSC entry for the app to resolve at the fixed NSC address.
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_dispatch");
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_handler");
}
