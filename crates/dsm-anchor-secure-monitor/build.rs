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

include!("../../scripts/real_code_guard_build.rs");

fn main() {
    if let Err(refusal) = real_code_guard() {
        eprintln!("{refusal}");
        std::process::exit(1);
    }
    if let Err(why) = build() {
        eprintln!("{why}");
        std::process::exit(1);
    }
}

/// A command's run, or why it did not run or did not succeed.
fn run(what: &str, command: &mut Command) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|e| format!("{what}: did not start: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what}: {status}"))
    }
}

fn build() -> Result<(), String> {
    println!("cargo:rerun-if-changed=veneer/dsm_sg_veneer.S");
    println!("cargo:rerun-if-changed=veneer/dsm_ns_payload.S");
    println!("cargo:rerun-if-changed=veneer/dsm_sg_abi.h");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=dsm-secure-sram.x");

    let out = PathBuf::from(env::var("OUT_DIR").map_err(|e| format!("OUT_DIR: {e}"))?);
    let manifest = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").map_err(|e| format!("CARGO_MANIFEST_DIR: {e}"))?,
    );
    let lib = out.join("libdsm_sg_veneer.a");

    // ── Build the real Non-secure app and objcopy its SRAM image into ns_app.bin (OUT_DIR), which
    // veneer/dsm_ns_payload.S `.incbin`s into .ns_app. A separate --target-dir avoids workspace lock
    // contention with this monitor build. This is the cross-crate NS packaging (replaces the stub).
    let ns_crate = manifest.join("../dsm-anchor-nonsecure-app");
    println!("cargo:rerun-if-changed={}/src/main.rs", ns_crate.display());
    println!(
        "cargo:rerun-if-changed={}/dsm-ns-sram.x",
        ns_crate.display()
    );
    println!("cargo:rerun-if-changed={}/memory.x", ns_crate.display());
    // A monitor update for a burned board carries the very image whose digest is in its OTP, not a
    // rebuild of it: `DSM_ANCHOR_NS_BIN` names the `ns_app.bin` sign.sh kept when that board was signed.
    println!("cargo:rerun-if-env-changed=DSM_ANCHOR_NS_BIN");
    let ns_bin = out.join("ns_app.bin");
    if let Some(kept) = env::var_os("DSM_ANCHOR_NS_BIN") {
        println!("cargo:rerun-if-changed={}", PathBuf::from(&kept).display());
        std::fs::copy(&kept, &ns_bin)
            .map_err(|e| format!("copy the kept Non-secure image: {e}"))?;
    } else {
        let ns_target = out.join("ns-app-target");
        let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        run(
            "build dsm-anchor-nonsecure-app",
            Command::new(&cargo)
                .current_dir(&ns_crate)
                .args(["build", "--release", "--target-dir"])
                .arg(&ns_target)
                // Do not inherit this monitor build's RUSTFLAGS/target; the NS crate's .cargo/config
                // sets its own (dsm-ns-sram.x). Clear the vars cargo would otherwise propagate.
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_TARGET"),
        )?;
        let ns_elf = ns_target.join("thumbv8m.main-none-eabihf/release/dsm-anchor-nonsecure-app");
        run(
            "objcopy the Non-secure app image",
            Command::new("arm-none-eabi-objcopy")
                .args(["-O", "binary"])
                .arg(&ns_elf)
                .arg(&ns_bin),
        )?;
    }

    // Assemble the reviewed asm (NSC veneer + the NS payload) with clang for ARMv8-M, archive both
    // into one static lib linked into the monitor. `-I <OUT_DIR>` lets the payload `.incbin ns_app.bin`.
    let mut objs = Vec::new();
    for src in ["veneer/dsm_sg_veneer.S", "veneer/dsm_ns_payload.S"] {
        let name = PathBuf::from(src)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{src} names no file"))?;
        let obj = out.join(format!("{name}.o"));
        run(
            &format!("clang assemble {src}"),
            Command::new("clang")
                .args([
                    "--target=arm-none-eabi",
                    "-mcpu=cortex-m33",
                    "-mfloat-abi=hard",
                    "-mfpu=fpv5-sp-d16",
                    "-I",
                ])
                .arg(&out)
                .args(["-c", src, "-o"])
                .arg(&obj),
        )?;
        objs.push(obj);
    }

    // A stale archive would keep members `ar crs` does not replace: it starts from none.
    match std::fs::remove_file(&lib) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove the old veneer archive: {e}")),
    }
    let mut ar = Command::new("arm-none-eabi-ar");
    ar.arg("crs").arg(&lib);
    for obj in &objs {
        ar.arg(obj);
    }
    run("ar the veneer archive", &mut ar)?;

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=dsm_sg_veneer");
    println!(
        "cargo:rustc-link-search={}",
        env::current_dir()
            .map_err(|e| format!("the build's directory: {e}"))?
            .display()
    );
    // The monitor does not CALL the gateway (the separate Non-secure app image does), so force the
    // veneer (and, transitively, the Secure handler it references) to be linked + kept, and export
    // the NSC entry for the app to resolve at the fixed NSC address.
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_dispatch");
    println!("cargo:rustc-link-arg=--undefined=dsm_secure_handler");
    // Keep the Non-secure app image (veneer/dsm_ns_payload.S): `main` launches it through its vector
    // table, `__ns_app_vector_table`, at the NS SRAM base.
    println!("cargo:rustc-link-arg=--undefined=__ns_app_vector_table");
    Ok(())
}
