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

    let descriptor_set = out_dir.join("dsm_app.fds");
    match prost_build::Config::new()
        .out_dir(&out_dir)
        .file_descriptor_set_path(&descriptor_set)
        .compile_protos(&[&proto_file], &[&proto_root, &vendored_include])
    {
        Ok(_) => println!("cargo:warning=Prost compilation succeeded"),
        Err(e) => {
            println!("cargo:warning=Prost compilation failed: {e}");
            return Err(e.into());
        }
    }
    write_envelope_payload_tags(&descriptor_set, &out_dir)?;

    // Also rerun if proto under workspace root changes
    println!("cargo:rerun-if-changed={}", proto_file.display());
    Ok(())
}

/// The strict envelope validator admits exactly the payload fields the proto
/// defines and names the numbers it reserves. Both lists are read from the
/// compiled descriptor of `dsm.Envelope`, so they cannot drift from the proto.
fn write_envelope_payload_tags(
    descriptor_set: &std::path::Path,
    out_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use prost::Message;

    let fds = prost_types::FileDescriptorSet::decode(std::fs::read(descriptor_set)?.as_slice())?;
    let envelope = fds
        .file
        .iter()
        .filter(|file| file.package() == "dsm")
        .flat_map(|file| file.message_type.iter())
        .find(|message| message.name() == "Envelope")
        .ok_or("the proto defines no dsm.Envelope")?;
    let payload_index = envelope
        .oneof_decl
        .iter()
        .position(|oneof| oneof.name() == "payload")
        .ok_or("dsm.Envelope has no payload oneof")?;
    let payload_index = i32::try_from(payload_index)?;

    let mut payload: Vec<i32> = envelope
        .field
        .iter()
        .filter(|field| field.oneof_index == Some(payload_index))
        .map(|field| field.number())
        .collect();
    payload.sort_unstable();
    let sealed = envelope
        .field
        .iter()
        .find(|field| field.oneof_index == Some(payload_index) && field.name() == "sealed")
        .ok_or("dsm.Envelope's payload oneof has no sealed field")?
        .number();
    // A descriptor's reserved range is end-exclusive.
    let mut reserved: Vec<i32> = envelope
        .reserved_range
        .iter()
        .flat_map(|range| range.start()..range.end())
        .collect();
    reserved.sort_unstable();

    let list = |tags: &[i32]| {
        tags.iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    std::fs::write(
        out_dir.join("envelope_payload_tags.rs"),
        format!(
            "/// The fields of `dsm.Envelope`'s `payload` oneof, from the proto.\n\
             pub(crate) const ENVELOPE_PAYLOAD_TAGS: &[u32] = &[{}];\n\
             /// The field numbers `dsm.Envelope` reserves, from the proto.\n\
             pub(crate) const ENVELOPE_RESERVED_TAGS: &[u32] = &[{}];\n\
             /// The sealed spool payload (DSM Amendment A7), from the proto.\n\
             pub(crate) const SEALED_PAYLOAD_TAG: u32 = {};\n",
            list(&payload),
            list(&reserved),
            sealed
        ),
    )?;
    Ok(())
}
