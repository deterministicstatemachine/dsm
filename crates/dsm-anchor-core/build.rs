//! Compile the in-crate anchor wire schema (proto/dsm_anchor.proto) with prost.
//! Generated code uses `prost::alloc`, so it builds for the no_std RP2350 firmware
//! (with a global allocator) as well as the host. Mirrors the DSM repo's
//! prost-build + protoc-bin-vendored setup.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Use the vendored protoc so no system protoc is required.
    env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    let include = protoc_bin_vendored::include_path()?;

    // proto/ lives inside this crate (self-contained workspace member).
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest.join("proto");
    let proto_file = proto_dir.join("dsm_anchor.proto");
    if !proto_file.exists() {
        return Err(format!("anchor proto not found: {}", proto_file.display()).into());
    }

    prost_build::Config::new()
        .out_dir(&out_dir)
        .compile_protos(&[&proto_file], &[&proto_dir, &include])?;

    println!("cargo:rerun-if-changed={}", proto_file.display());
    Ok(())
}
