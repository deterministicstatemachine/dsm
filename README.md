# DSM Workspace

> **🚧 EARLY BETA RELEASE** 🚧
>
> This is an early beta release intended for **developer onboarding and community feedback**. It contains novel cryptographic protocols and is not yet ready for production use or end-user deployment. The codebase is under active development with known gaps remaining before mainnet readiness.
>
> **Target Audience:** Developers interested in post-quantum cryptography, deterministic protocols, and decentralized finance. Not recommended for end-users or production systems.

## Documentation

- **[Developer Handbook](docs/book/README.md)** — Architecture, setup, testing, and complete reference
- **[DSM Primitive Paper](docs/papers/dsm_primitive.pdf)** — Boundary, definition, and composition of the core primitive
- **[Quickstart](QUICKSTART.md)** — Zero to running in under 30 minutes
- **[Code Generation (`dsm-gen`)](dsm-gen/README.md)** — Typed DLV and policy clients, schema validation, onboarding workflow
- **[Contributing](CONTRIBUTING.md)** — How to contribute
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Community participation standards
- **[Security](SECURITY.md)** — Private vulnerability reporting process
- **[Support](SUPPORT.md)** — Where to ask for help and where to file issues
- **[Changelog](CHANGELOG.md)** — Version history

---

This repository contains the Deterministic State Machine (DSM) workspace: the Rust core and SDK, the DSM Wallet Android app (WebView + JNI/NDK), React frontend bundle, and a six-node production storage cluster on AWS (three regions).

Highlights
- Post-quantum, clockless protocol. Envelope v3 only. Protobuf transport only (no JSON envelopes).
- Binary-first: bytes in Core; Base32 Crockford only at UI/string boundaries for display/QR. Hex is banned.
- BLE path is protobuf-only via BleCommand/BleCommandResponse routed through the SDK.
- Storage nodes are index-only HTTP persistence: they never sign or validate protocol rules.
- `dsm-gen` turns vault and policy specifications into typed clients and schemas for DLV, token, and integration work.

If you're looking for the normative protocol text and updated architecture, read these first:
- [Developer Handbook](docs/book/README.md)
- [Protocol Reference](docs/book/05-protocol-reference.md)
- [Storage Nodes](docs/book/07-storage-nodes.md)
- [Hard Invariants](docs/book/appendix-b-hard-invariants.md)
- [Spec Index](docs/book/appendix-c-spec-index.md)
- [Proto Schema](proto/dsm_app.proto)

If you're contributing:
- Start with [Contributing](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Security](SECURITY.md).
- If your work touches DLVs, policies, or generated clients, read [the `dsm-gen` guide](dsm-gen/README.md) and [Chapter 16 of the handbook](docs/book/16-code-generation.md).

## Platform Support

| Workflow | macOS | Linux | Windows | Notes |
|----------|-------|-------|---------|-------|
| Rust core / SDK development | Yes | Yes | Yes | Use `make` on macOS/Linux and `.\scripts\dev.ps1` on Windows |
| Frontend development | Yes | Yes | Yes | Node.js 20+ required |
| Local storage node development (optional) | Yes | Yes | Yes | PostgreSQL required |
| `dsm-gen` workflows | Yes | Yes | Yes | Cargo-based generator and schema tooling |
| Android APK build / install | Yes | Yes | WSL2 | Native Windows Android builds are not supported |
| Bash / Zsh helper scripts | Yes | Yes | WSL2 | Most `.sh` and `.zsh` helpers assume a Unix shell |

Windows contributors can work natively on the Rust workspace, frontend, storage nodes, and `dsm-gen`. Android builds and shell-heavy helper flows should be run from WSL2.

## Quick start

Primary entry point on macOS and Linux:

```bash
make help
make menu
make doctor
```

On Windows, use `.\scripts\dev.ps1 help` instead.

Most Windows contributors can stay native for day-to-day work. Switch to WSL2 only when you need Android builds or Unix-only helper scripts.
The maintained shell workflow is intentionally small: prefer `make`, `.\scripts\dev.ps1`, and the documented scripts in the handbook over ad hoc top-level helpers.

### Storage Nodes

The default configuration connects to 6 production storage nodes on AWS (us-east-1, eu-west-1, ap-southeast-1). With outbound internet access, no local setup is required.

For optional local development nodes, see [Storage Nodes](docs/book/07-storage-nodes.md#local-multi-node-development).

### Build Everything

Base prerequisites
- Rust toolchain (stable), protoc
- Node.js + npm

Android prerequisites (only for `make android`, `make android-libs`, or `make install`)
- Android SDK/NDK + Java 17
- Optional: cargo-ndk for building native Android libs

Build everything (Rust + TypeScript)
```bash
make build
make frontend
```

Run onboarding validation
```bash
make typecheck
```

If you are working on DLVs, policies, or generated clients, also verify the generator entry point:

```bash
cargo run -p dsm-gen -- --help
```

`make test`, `make test-rust`, and `make test-frontend` are broader development suites, not the initial smoke check. See [Testing and CI](docs/book/10-testing-and-ci.md) for the full matrix and caveats.

## Android app (NDK/JNI + WebView)

The Android app is a Kotlin container that:
- Loads the Rust core via JNI (built with cargo-ndk as libdsm_sdk.so for all ABIs)
- Serves the React bundle from assets/web/
- Bridges UI ↔ SDK via a binary MessagePort channel carrying Envelope v3 protobuf bytes

Build the WebView bundle and assemble a debug APK:
```bash
make android
```

Optionally build the native library for all ABIs with cargo-ndk (if you need to refresh JNI libs):
```bash
make android-libs
```

See the [Developer Handbook](docs/book/README.md) for full NDK build instructions including `.so` copy steps and symbol verification.

## Storage Nodes (6-node AWS cluster)

DSM storage nodes are dumb persistence services (no signatures, no validation). The production cluster runs 6 nodes across 3 AWS regions:

| Node | Region | IP |
|------|--------|----|
| dsm-node-1 | us-east-1 | 13.218.83.69 |
| dsm-node-2 | us-east-1 | 44.223.31.184 |
| dsm-node-3 | eu-west-1 | 54.74.145.172 |
| dsm-node-4 | eu-west-1 | 3.249.79.215 |
| dsm-node-5 | ap-southeast-1 | 18.141.56.252 |
| dsm-node-6 | ap-southeast-1 | 13.215.175.231 |

The app config (`dsm_env_config.toml`) ships with these nodes as the default. With outbound internet access, no local setup is required.

For optional local development nodes (offline dev without AWS), see [Storage Nodes](docs/book/07-storage-nodes.md#local-multi-node-development).

## BLE command path (PROTO-only)

The SDK exposes a ble.command route that:
- Accepts an Envelope v3 UniversalTx carrying an ArgPack { codec=PROTO, body=BleCommand }
- Dispatches to a registered BLE backend (or returns a deterministic “no-backend” error)
- Returns a ResultPack { codec=PROTO, body=BleCommandResponse }

Frontend normalizes oneof/binary fields and calls this route via the existing bridge.

## Determinism & bans (production gates)

- No wall-clock markers anywhere in protocol or Core logic; ordering is hash-adjacency only.
- No JSON envelopes; protobuf-only transport. Never hash/sign protobuf bytes; always use canonical commit bytes emitted by the Core.
- Hex/base64 are display or I/O edge only (UI, QR, BLE packet dumps); Core stays binary.
- Envelope version is 3; strict-fail if not 3. No v2.

See [Hard Invariants](docs/book/appendix-b-hard-invariants.md) and [Testing and CI](docs/book/10-testing-and-ci.md) for the public ban list and CI scan surface.

## MPC-only genesis and auth

Genesis is created exclusively via the MPC service configured in your packaged TOML.

- Set dsm.network.mpc_genesis_url to your MPC endpoint
- Optionally set dsm.network.mpc_api_key to attach Authorization: Bearer at runtime
- Verify behavior via logs (keys are never printed):
  - "MPC genesis: Authorization header present (api key configured)"
  - "mpc_api_key provided but empty; request will be unauthenticated"
  - "no mpc_api_key configured; request will be unauthenticated"
  - "STRICT: mpc_genesis_url missing… cannot create genesis"

See the [Developer Handbook](docs/book/README.md), [DSM Primitive Paper](docs/papers/dsm_primitive.pdf), and [Proto Schema](proto/dsm_app.proto) for the public protocol references.

## What's authoritative?

Authoritative (read these):
- `docs/book/` handbook chapters and appendices
- `docs/papers/` papers and design notes
- `proto/dsm_app.proto` plus generated stubs

## What can you do with DSM?

Assuming the protocol and implementations are fully audited and battle-tested, DSM is intended to support:

- Building apps on a deterministic state and identity layer instead of ad hoc backend trust.
- Securing apps at the primitive layer, then composing higher-level secure application logic on top.
- General-purpose applications centered on value transfer, coordination, credentials, and sovereign identity.
- Deterministic sovereign finance: bilateral flows, self-custodied state, and offline-capable transactions.
- Bitcoin-native off-chain coordination and dBTC-style flows that aim to inherit Bitcoin's proof-of-work trust base rather than add a separate wrapped-asset trust layer.
- Instant counterparty finality, including offline finality for bilateral exchanges.
- Gas-free DSM-native coordination, with Bitcoin network fees only when entering or exiting the Bitcoin chain.
- Direct peer-to-peer Bitcoin experiences with no platform tolls inside the DSM layer.
- Verifiable creator, AI, and agent systems where identity, authorship, and receipts can be proved instead of asserted.

## Troubleshooting
- Android build: ensure Java 17 and Android SDK/NDK are installed; if JNI libs mismatch ABIs, rebuild with cargo-ndk (see above).
- Storage-node connectivity: the default config points to AWS nodes over HTTPS. If you run local dev nodes instead, ensure PostgreSQL is running and use `make nodes-up`.
- Protobuf drift: regenerate after editing `proto/dsm_app.proto` and rebuild all packages.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
