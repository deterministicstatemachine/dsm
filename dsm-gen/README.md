# `dsm-gen`

`dsm-gen` is the DSM specification-driven code generator. It turns vault and policy specifications into typed client code, exports JSON schema for tooling, and validates authoring input before those specs reach the SDK or frontend.

This tool matters when you are:

- authoring Deterministic Limbo Vault (DLV) specifications
- defining DSM token or transfer policies
- generating typed integration code for TypeScript, Kotlin, Swift, or Rust
- validating that your spec shape still matches the canonical protobuf model

## What it Generates

`dsm-gen` works from YAML or JSON specifications whose top-level `type` is either `vault` or `policy`.

- `vault` specs describe DLV-style state machines, fulfillment conditions, assets, tick locks, and recovery rules
- `policy` specs describe rule-based constraints and approvals for DSM operations

The generator currently supports:

- `ts`
- `kotlin`
- `swift`
- `rust`

## Repo-Root Usage

Run all commands from the repository root:

```bash
# Show commands and flags
cargo run -p dsm-gen -- --help

# Validate a specification
cargo run -p dsm-gen -- validate path/to/spec.yaml

# Generate a typed client
cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts

# Generate multiple clients into a directory
cargo run -p dsm-gen -- --output-dir ./generated client path/to/spec.yaml --lang kotlin,swift

# Export JSON schema for editors or CI checks
cargo run -p dsm-gen -- schema vault --output ./vault-schema.json
cargo run -p dsm-gen -- schema policy --output ./policy-schema.json

# Scaffold a new spec-first project
cargo run -p dsm-gen -- init my-dsm-project
```

## Typical Workflow

1. Author or update a vault or policy spec.
2. Validate it with `dsm-gen validate`.
3. Export the schema if you need editor integration or CI-side validation.
4. Generate typed client code for the language your integration uses.
5. Commit the spec and any generated artifacts your package owns.

## Type Safety and Drift Detection

`dsm-gen` is not just a text templater. Its schema types mirror the canonical protobuf model in [proto/dsm_app.proto](../proto/dsm_app.proto), including DLV fulfillment structures such as Bitcoin HTLC conditions.

When `protoc` is available, `dsm-gen` compiles those protobuf types during build and enforces structural parity at compile time. If your local repo layout is unusual, set `DSM_PROTO_ROOT` to the directory that contains `dsm_app.proto`.

## Where to Read Next

- [Developer handbook chapter: Code Generation](../docs/book/16-code-generation.md)
- [Developer handbook chapter: Integration Guide](../docs/book/11-integration-guide.md)
- [Canonical protobuf schema](../proto/dsm_app.proto)
