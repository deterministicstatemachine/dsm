// Build scripts are allowed to use unwrap/expect/panic for setup operations
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::disallowed_methods)]

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn rustc_version() -> Result<String, Box<dyn std::error::Error>> {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(rustc).arg("--version").output()?;
    if !output.status.success() {
        return Err("failed to query rustc version".into());
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let vendored_include = protoc_bin_vendored::include_path()?;
    let target = env::var("TARGET")?;
    let rustc_version = rustc_version()?;

    println!("cargo:rustc-env=DSM_BUILD_TARGET={target}");
    println!("cargo:rustc-env=DSM_RUSTC_VERSION={rustc_version}");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=TARGET");

    // Canonical schema location is the repository root at `proto/`.
    // Allow override via DSM_PROTO_ROOT, but default to the repo-root canonical path.
    let proto_root = env::var("DSM_PROTO_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
            let manifest_path = PathBuf::from(manifest_dir);
            // .../dsm_client/deterministic_state_machine/dsm → up to repo root
            let repo_root = manifest_path
                .parent() // deterministic_state_machine
                .expect("Failed to resolve deterministic_state_machine directory")
                .parent() // dsm_client
                .expect("Failed to resolve dsm_client directory")
                .parent() // dsm
                .expect("Failed to resolve repo root");
            repo_root.join("proto")
        });

    let proto_file = proto_root.join("dsm_app.proto");

    // Check proto file exists, fail with clear error if not
    if !proto_file.exists() {
        panic!(
            "Proto file not found: {}\nSet DSM_PROTO_ROOT or check your workspace structure.",
            proto_file.display()
        );
    }

    match prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(&[&proto_file], &[&proto_root, &vendored_include])
    {
        Ok(_) => println!("cargo:warning=Prost compilation succeeded"),
        Err(e) => {
            println!("cargo:warning=Prost compilation failed: {e}");
            return Err(e.into());
        }
    }

    // Also rerun if proto under workspace root changes
    println!("cargo:rerun-if-changed={}", proto_file.display());
    Ok(())
}
