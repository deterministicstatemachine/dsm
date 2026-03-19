# Chapter 16 — Code Generation

How to use `dsm-gen` to validate DSM specifications and generate typed clients for DLV and policy work.

---

## What `dsm-gen` Is For

`dsm-gen` is the specification-driven generator for DSM vault and policy definitions.

Use it when you need to:

- construct Deterministic Limbo Vault (DLV) specifications without hand-assembling runtime payloads
- define policy specifications in a format that can be validated and shared across teams
- generate typed client builders for TypeScript, Kotlin, Swift, or Rust
- keep spec shapes aligned with the canonical protobuf contract in `proto/dsm_app.proto`

The generator is part of the public developer workflow. It is not just an internal build helper.

---

## Supported Inputs

`dsm-gen` accepts YAML or JSON specifications whose top-level `type` is:

- `vault` for DLV-style specifications, fulfillment conditions, assets, tick locks, and recovery rules
- `policy` for rule-based approvals and operation constraints

The underlying schema types in `dsm-gen/src/schema.rs` mirror the protobuf model closely enough to catch drift when the proto changes.

---

## Standard Workflow

Run these commands from the repository root:

```bash
# Confirm the CLI surface
cargo run -p dsm-gen -- --help

# Validate a specification before generating anything
cargo run -p dsm-gen -- validate path/to/spec.yaml

# Generate a typed client for one language
cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts

# Generate multiple client targets into a directory
cargo run -p dsm-gen -- --output-dir ./generated client path/to/spec.yaml --lang kotlin,swift

# Export JSON schema for editor tooling or CI-side validation
cargo run -p dsm-gen -- schema vault --output ./vault-schema.json
```

Recommended order:

1. Author the spec.
2. Run `validate`.
3. Generate clients for the integration layer that consumes the spec.
4. Re-run the relevant tests for the crate or app that uses the generated output.

---

## DLV and Policy Construction

For DLV work, the important point is that `dsm-gen` gives you a typed authoring path instead of manually stitching together nested fulfillment structures.

Examples of spec concepts represented in the generator schema:

- multi-signature fulfillment
- state-reference fulfillment
- Bitcoin HTLC fulfillment for dBTC flows
- asset definitions and chain-state references
- iteration-based tick locks instead of wall-clock expiry
- recovery mechanisms

For policy work, the same pattern applies: define the rules declaratively, validate them, then generate client-facing types instead of duplicating those structures across apps.

---

## Type Safety and Proto Drift

`proto/dsm_app.proto` is the canonical source of truth for DSM wire structures.

When `protoc` is available, `dsm-gen` builds against that proto during compilation and enables compile-time drift detection between the generator schema and the protobuf model. This is especially important for DLV-related fulfillment types where silent divergence would be expensive.

If your environment needs a custom proto location, set:

```bash
export DSM_PROTO_ROOT=/absolute/path/to/proto
```

Point it at the directory that contains `dsm_app.proto`.

---

## Where It Fits in the Handbook

- Read [Chapter 11 — Integration Guide](11-integration-guide.md) if you are replacing the frontend or building another client surface.
- Read [Chapter 12 — Command Reference](12-command-reference.md) for the raw CLI commands.
- Read [`dsm-gen/README.md`](../../dsm-gen/README.md) for the tool-specific overview.

---

Next: review the surrounding integration and command-reference chapters as needed.
