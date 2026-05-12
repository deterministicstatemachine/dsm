# DSM Quickstart

This is the shortest supported path from clone to a working DSM developer environment.

The repository now has one primary entry point on macOS and Linux:

```bash
make help
make menu
make doctor
```

Use `.\scripts\dev.ps1` on Windows instead of `make`.

## Platform Support

| Workflow | macOS | Linux | Windows |
|----------|-------|-------|---------|
| Android APK build/install | Yes | Yes | WSL2 |
| Local storage nodes (optional) | Yes | Yes | Yes |
| Bash/Zsh helper scripts | Yes | Yes | WSL2 |

Windows contributors can do normal development natively. Use WSL2 when you need Android builds or Unix-only helper scripts.

## What You Get

- Rust workspace built
- Frontend dependencies installed
- App configured to connect to 6 production AWS storage nodes (no local setup required)
- Base Rust/frontend toolchain validated with the supported onboarding commands
- Optional Android APK build and device install

## Storage Nodes

The default app config (`dsm_env_config.toml`) ships pre-configured to connect to 6 production storage nodes on AWS:

| Node | Region | IP |
|------|--------|----|
| dsm-node-1 | us-east-1 | 13.218.83.69 |
| dsm-node-2 | us-east-1 | 44.223.31.184 |
| dsm-node-3 | eu-west-1 | 54.74.145.172 |
| dsm-node-4 | eu-west-1 | 3.249.79.215 |
| dsm-node-5 | ap-southeast-1 | 18.141.56.252 |
| dsm-node-6 | ap-southeast-1 | 13.215.175.231 |

No local PostgreSQL or local node setup is needed for normal development and testing. With outbound internet access, the app connects to these nodes over HTTPS.

For optional local development nodes (offline dev without internet), see [docs/book/07-storage-nodes.md](docs/book/07-storage-nodes.md#local-multi-node-development).

## Prerequisites

macOS:

```bash
brew install git protobuf node
brew install --cask temurin@17
```

Linux (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y build-essential git curl protobuf-compiler nodejs npm openjdk-17-jdk
```

All platforms:

- Rust via [rustup.rs](https://rustup.rs) (the repo pins `1.91.0` in `rust-toolchain.toml`)
- Android Studio + Android NDK `27.0.12077973` if you want Android builds
- `cargo-ndk` if you want Android native builds
- Set `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) before `make android`, `make android-libs`, or `make install`

Windows:

- Use PowerShell
- Run `.\scripts\dev.ps1 setup`
- Android builds require WSL2; see [docs/book/03-development-setup.md](docs/book/03-development-setup.md)

## Clone

```bash
git clone https://github.com/irrefutable-labs/dsm.git
cd dsm
```

## One-Stop Setup

Check the machine first:

```bash
make doctor
```

Install frontend dependencies and generate the Android cargo config:

```bash
make setup
```

`make setup` is valid before Android tooling is installed. It only writes the Android cargo config when `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` is set. `make doctor` and `make setup` both report the pinned Rust version, the resolved NDK root, the detected host tag, and the generated Android cargo-config status when Android tooling is present.

Build the Rust workspace:

```bash
make build
```

Run the onboarding validation pass:

```bash
make typecheck
```

## Broader Test Suites

The full test entry points are broader than the onboarding smoke check:

```bash
make test-rust
make test-frontend
make test
```

`make test-rust` includes SDK integration coverage beyond pure unit tests, and some of that coverage expects the configured storage network to be reachable. `make test-frontend` runs the full Jest/UI suite; use `make typecheck` for the fastest baseline validation.

## Android

Build the debug APK:

```bash
make android
```

Build and install on all connected devices:

```bash
make install
```

The app connects to the AWS storage nodes by default. No port forwarding is required.

Refresh only the JNI libraries:

```bash
make android-libs
```

This is the canonical wrapper around:

```bash
cd dsm_client/deterministic_state_machine
DSM_PROTO_ROOT=/absolute/path/to/dsm/proto \
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o /absolute/path/to/dsm/dsm_client/android/app/src/main/jniLibs \
  --platform 23 build --release --package dsm_sdk --features=jni,bluetooth
```

The Makefile then mirrors the built `.so` files into `dsm_client/deterministic_state_machine/jniLibs/` as well.

## `dsm-gen`

If you are working on DLVs, policies, or generated integration clients:

```bash
cargo run -p dsm-gen -- --help
cargo run -p dsm-gen -- validate dsm-gen/test-vault.yaml
cargo run -p dsm-gen -- validate dsm-gen/test-policy.yaml
```

Then read [dsm-gen/README.md](dsm-gen/README.md) and [docs/book/16-code-generation.md](docs/book/16-code-generation.md).

## Bitcoin / dBTC

Bitcoin testing is signet-backed. There is no local Bitcoin node workflow in this repository.

See [docs/book/08-bitcoin-dbtc.md](docs/book/08-bitcoin-dbtc.md).

## Optional: Local Storage Nodes

If you need to develop offline or test against local nodes:

```bash
# Requires PostgreSQL
make nodes-up      # start 5 local nodes on ports 8080-8084
make nodes-status  # verify health
make nodes-down    # stop nodes
make nodes-reset   # stop and clean logs/pids
```

To point the Android app at local nodes, push a localhost override:

```bash
scripts/push_env_override.sh --local
```

## Troubleshooting

- `make doctor` shows what is missing before you start changing files.
- If Android build prerequisites drift, rerun `make setup`.
- If frontend assets drift, rerun `make frontend`.
- For local node issues: ensure PostgreSQL is running, then `make nodes-reset && make nodes-up`.

For deeper setup and platform-specific guidance:

- [README.md](README.md)
- [docs/book/02-quickstart.md](docs/book/02-quickstart.md)
- [docs/book/03-development-setup.md](docs/book/03-development-setup.md)
- [docs/book/12-command-reference.md](docs/book/12-command-reference.md)
