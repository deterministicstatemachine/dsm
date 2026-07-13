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
    println!("cargo:rerun-if-changed=veneer/dsm_ns_payload.S");
    println!("cargo:rerun-if-changed=veneer/dsm_sg_abi.h");
    println!("cargo:rerun-if-changed=memory.x");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib = out.join("libdsm_sg_veneer.a");

    // ── Build the real Non-secure app and objcopy its SRAM image into ns_app.bin (OUT_DIR), which
    // veneer/dsm_ns_payload.S `.incbin`s into .ns_app. A separate --target-dir avoids workspace lock
    // contention with this monitor build. This is the cross-crate NS packaging (replaces the stub).
    let ns_crate = manifest.join("../dsm-anchor-nonsecure-app");
    println!("cargo:rerun-if-changed={}/src/main.rs", ns_crate.display());
    println!("cargo:rerun-if-changed={}/dsm-ns-sram.x", ns_crate.display());
    println!("cargo:rerun-if-changed={}/memory.x", ns_crate.display());
    let ns_target = out.join("ns-app-target");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(&cargo)
        .current_dir(&ns_crate)
        .args(["build", "--release", "--target-dir"])
        .arg(&ns_target)
        // Do not inherit this monitor build's RUSTFLAGS/target; the NS crate's .cargo/config sets its
        // own (dsm-ns-sram.x). Clear the vars cargo would otherwise propagate.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_TARGET")
        .status()
        .expect("build dsm-anchor-nonsecure-app");
    assert!(status.success(), "Non-secure app build failed");
    let ns_elf = ns_target.join("thumbv8m.main-none-eabihf/release/dsm-anchor-nonsecure-app");
    let ns_bin = out.join("ns_app.bin");
    let status = Command::new("arm-none-eabi-objcopy")
        .args(["-O", "binary"])
        .arg(&ns_elf)
        .arg(&ns_bin)
        .status()
        .expect("objcopy the Non-secure app image");
    assert!(status.success(), "objcopy of the Non-secure app failed");

    // Assemble the reviewed asm (NSC veneer + the NS payload) with clang for ARMv8-M, archive both
    // into one static lib linked into the monitor. `-I <OUT_DIR>` lets the payload `.incbin ns_app.bin`.
    let mut objs = Vec::new();
    for src in ["veneer/dsm_sg_veneer.S", "veneer/dsm_ns_payload.S"] {
        let obj = out.join(format!("{}.o", src.rsplit('/').next().unwrap()));
        let status = Command::new("clang")
            .args([
                "--target=arm-none-eabi",
                "-mcpu=cortex-m33",
                "-mfloat-abi=hard",
                "-mfpu=fpv5-sp-d16",
                "-I",
            ])
            .arg(&out)
            .args(["-c", src, "-o"])
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
