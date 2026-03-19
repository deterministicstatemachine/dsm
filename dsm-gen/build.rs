// build.rs — compile dsm_app.proto into $OUT_DIR/dsm.rs
//
// Invariant #7: proto is the single source of truth for DSM types.
// This build script ensures dsm-gen's schema types stay in sync with the
// canonical proto definition. The compiled prost types are exposed via
// `crate::schema::proto` so schema.rs can provide a `From` impl that
// produces a compile-error the moment the two diverge.

use std::path::PathBuf;

fn default_proto_root() -> PathBuf {
    std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| PathBuf::from(d).join("../proto"))
        .unwrap_or_else(|_| PathBuf::from("../proto"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Allow an override for CI environments where the proto root differs.
    let proto_root = std::env::var_os("DSM_PROTO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(default_proto_root);
    let proto_file = proto_root.join("dsm_app.proto");

    // Rerun if proto or this script changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    println!("cargo:rerun-if-env-changed=DSM_PROTO_ROOT");

    // Declare the custom cfg so check-cfg doesn't warn about it.
    println!("cargo::rustc-check-cfg=cfg(dsm_proto_compiled)");

    // Attempt proto compilation.  If protoc is not installed or the path is
    // wrong, emit a warning and skip — the crate still compiles, but the
    // `proto` module gate in schema.rs disables the From-impl enforcement.
    match prost_build::Config::new()
        .compile_protos(&[proto_file.as_path()], &[proto_root.as_path()])
    {
        Ok(()) => {
            println!("cargo:rustc-cfg=dsm_proto_compiled");
        }
        Err(e) => {
            println!(
                "cargo:warning=dsm-gen: proto compilation skipped ({e}). \
                 Install protoc and set DSM_PROTO_ROOT to the directory \
                 containing dsm_app.proto to enable drift detection."
            );
        }
    }

    Ok(())
}
