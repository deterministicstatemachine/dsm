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
    println!("cargo:rerun-if-changed=veneer/dsm_ns_stub.S");
    println!("cargo:rerun-if-changed=veneer/dsm_sg_abi.h");
    println!("cargo:rerun-if-changed=memory.x");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib = out.join("libdsm_sg_veneer.a");

    // Assemble the reviewed asm (NSC veneer + the bring-up NS stub) with clang for ARMv8-M, archive
    // both into one static lib linked into the monitor.
    let mut objs = Vec::new();
    for src in ["veneer/dsm_sg_veneer.S", "veneer/dsm_ns_stub.S"] {
        let obj = out.join(format!("{}.o", src.rsplit('/').next().unwrap()));
        let status = Command::new("clang")
            .args([
                "--target=arm-none-eabi",
                "-mcpu=cortex-m33",
                "-mfloat-abi=hard",
                "-mfpu=fpv5-sp-d16",
                "-c",
                src,
                "-o",
            ])
            .arg(&obj)
            .status()
            .unwrap_or_else(|_| panic!("clang assemble {src}"));
        assert!(status.success(), "assembly failed: {src}");
        objs.push(obj);
    }

    let _ = std::fs::remove_file(&lib);
    let mut ar = Command::new("arm-none-eabi-ar");
    ar.arg("crs").arg(&lib);
    for obj in &objs {
        ar.arg(obj);
    }
    assert!(ar.status().expect("ar").success(), "ar failed");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=dsm_sg_veneer");
    println!("cargo:rustc-link-search={}", env::current_dir().unwrap().display());
    // The monitor does not CALL the gateway (the separate Non-secure app image does), so force the
    // veneer (and, transitively, the Secure handler it references) to be linked + kept, and export
    // the NSC entry for the app to resolve at the fixed NSC address.
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_dispatch");
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_handler");
    // Keep the bring-up NS stub (nothing in Rust references it; the linker places it in NS SRAM and
    // the monitor branches to its vector table by fixed address).
    println!("cargo:rustc-link-arg=--undefined=__ns_app_vector_table");
}
