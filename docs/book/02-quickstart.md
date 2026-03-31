# Chapter 2 — Quickstart

Get from zero to a running DSM development environment in under 30 minutes. Every command is copy-paste.

**What you will have at the end:**
- The Rust core and SDK compiled
- The app configured to connect to 6 production AWS storage nodes (no local setup required)
- The base Rust/frontend toolchain validated with the supported onboarding commands
- (Optional) The DSM Wallet app installed on an Android phone
- (Optional) A Bitcoin signet setup for dBTC testing

----

## Prerequisites

| Tool | macOS | Linux | Windows |
|------|-------|-------|---------|
| Git | `brew install git` | `sudo apt install git` | [git-scm.com](https://git-scm.com) |
| Rust | [rustup.rs](https://rustup.rs) | [rustup.rs](https://rustup.rs) | [rustup.rs](https://rustup.rs) |
| Node.js 20+ | `brew install node` | `sudo apt install nodejs npm` | [nodejs.org](https://nodejs.org) |
| protoc | `brew install protobuf` | `sudo apt install protobuf-compiler` | [protobuf releases](https://github.com/protocolbuffers/protobuf/releases) |

> **Windows users:** Use PowerShell and `scripts\dev.ps1` instead of `make`. Android APK builds require WSL2 — see [Chapter 3](03-development-setup.md#windows-setup).

PostgreSQL is only needed if you want to run local storage nodes for offline development. The default config connects to AWS.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/irrefutable-labs/dsm.git
cd dsm
```

All remaining commands run from the `dsm` root directory.

---

## Step 2 — Check the Machine and Build

```bash
make doctor
make setup
make build
```

`make setup` is valid before Android tooling is installed. It only generates the Android cargo config when `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` is configured.

First build takes 3–8 minutes (downloading and compiling all dependencies). You will see many `Compiling ...` lines — wait for `Finished`.

This compiles:
- `dsm` — cryptographic core (SPHINCS+, ML-KEM-768, BLAKE3)
- `dsm_sdk` — SDK layer (bridge, storage, identity)
- `dsm_storage_node` — storage node binary
- All supporting crates

If you are contributing to DLVs, policies, or generated integration clients, verify the generator from the repo root:

```bash
cargo run -p dsm-gen -- --help
```

Then read [Chapter 16 — Code Generation](16-code-generation.md).

---

## Step 3 — Storage Nodes (Already Running)

The default config (`dsm_env_config.toml`) connects to 6 production storage nodes on AWS:

| Node | Region | IP |
|------|--------|----|
| dsm-node-1 | us-east-1 | 13.218.83.69 |
| dsm-node-2 | us-east-1 | 44.223.31.184 |
| dsm-node-3 | eu-west-1 | 54.74.145.172 |
| dsm-node-4 | eu-west-1 | 3.249.79.215 |
| dsm-node-5 | ap-southeast-1 | 18.141.56.252 |
| dsm-node-6 | ap-southeast-1 | 13.215.175.231 |

With outbound HTTPS access, no local setup, PostgreSQL, or port forwarding is required.

For optional local development nodes (offline dev), see [Chapter 7 — Storage Nodes](07-storage-nodes.md#local-multi-node-development).

---

## Step 4 — Run Onboarding Validation

```bash
make typecheck
```

If you are contributing to DLVs, policies, or generated integration clients, also verify the generator entry point:

```bash
cargo run -p dsm-gen -- --help
```

## Broader Test Suites

Use the broader development suites after the toolchain is up:

```bash
make test-rust
make test-frontend
make test
```

`make test-rust` includes SDK integration coverage beyond pure unit tests, and some of that coverage expects the configured storage network to be reachable. `make test-frontend` runs the full Jest/UI suite; `make typecheck` remains the fastest onboarding validation step.

## You're Done

**What you have now:**
- Rust core and SDK compiled
- App configured to connect to 6 AWS storage nodes over HTTPS
- Frontend type-check passing

---

## Optional: Build the Android App

### Prerequisites

- Android Studio with NDK 27.x (Tools → SDK Manager → SDK Tools → NDK)
- Java 17 (`brew install --cask temurin@17` on macOS)
- `cargo-ndk` (`cargo install cargo-ndk`)
- `ANDROID_NDK_HOME` set in your shell profile before Android builds

### One-command build + install

```bash
make install
```

This builds native libraries (3 ABIs), the React frontend, packages the debug APK, and installs it on all connected USB devices. Takes 5–10 minutes on first build.

### Manual steps (if `make install` fails)

```bash
# 1. Build native .so files
make android-libs

# 2. Build frontend
cd dsm_client/frontend && npm install && npm run build && cd ../..

# 3. Assemble APK
cd dsm_client/android && ./gradlew :app:assembleDebug && cd ../..

# 4. Install on connected device
adb install -r dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```

The app connects to the AWS storage nodes by default. No port forwarding is needed.

---

## Optional: Bitcoin Signet

For dBTC testing, use the public Bitcoin signet network. No local Bitcoin node is required:

```bash
bitcoin_network = "signet"
```

See [Chapter 8 — Bitcoin and dBTC](08-bitcoin-dbtc.md) for the full HTLC workflow guide.

---

## Quick Troubleshooting

| Problem | Fix |
|---------|-----|
| `cargo build` fails with "linker not found" | macOS: `xcode-select --install`; Linux: `sudo apt install build-essential` |
| `cargo build` fails with "protoc not found" | macOS: `brew install protobuf`; Linux: `sudo apt install protobuf-compiler` |
| App shows "connection error" | Check internet connectivity to AWS nodes |
| `adb: command not found` | macOS: `brew install android-platform-tools` |
| `make: command not found` (Windows) | Use `.\scripts\dev.ps1` instead |

For comprehensive troubleshooting, see [Chapter 13](13-troubleshooting.md).

---

## Next Steps

| Goal | Go To |
|------|-------|
| Full dev environment setup | [Chapter 3 — Development Setup](03-development-setup.md) |
| Understand the architecture | [Chapter 4 — Architecture](04-architecture.md) |
| Learn the hidden app dev flows | [Chapter 18 — In-App Developer Walkthroughs](18-in-app-developer-walkthroughs.md) |
| Run Bitcoin integration tests | [Chapter 8 — Bitcoin and dBTC](08-bitcoin-dbtc.md) |
| Test BLE transfers | [Chapter 9 — BLE Testing](09-ble-testing.md) |
| See all available commands | [Chapter 12 — Command Reference](12-command-reference.md) |

---

Next: [Chapter 3 — Development Setup](03-development-setup.md)
