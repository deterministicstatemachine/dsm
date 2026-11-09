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
| iOS app (Simulator or device) | Yes | No | No |
| Local storage nodes (optional) | Yes | Yes | Yes (`scripts/dev.ps1`) |
| Plugging an app into DSM (`make app-dev`) | Yes | Yes | WSL2 |
| Bash/Zsh helper scripts | Yes | Yes | WSL2 |

Windows contributors can do normal development natively. Use WSL2 when you need Android builds or Unix-only helper scripts.

## What You Get

- Rust workspace built
- Frontend dependencies installed
- The wallet configured for the beta storage set (no local setup required)
- Base Rust/frontend toolchain validated with the supported onboarding commands
- Optional Android APK build and device install, and the iOS app in the Simulator or on a device
- Optionally, your own storage set on this machine, and everything you need to plug an app into DSM ([BUILDING_APPS.md](BUILDING_APPS.md))

## Storage Nodes

The wallet ships configured for the network's beta storage set: the five pinned members `dsm-node-1` to `dsm-node-5`, their endpoints, register incarnations and CA in [`dsm_client/frontend/public/dsm_env_config.toml`](dsm_client/frontend/public/dsm_env_config.toml). A test pins that file to the set the code commits to. With outbound internet access, the app reaches them over HTTPS; no local PostgreSQL or local node is needed.

To develop without depending on any hosted node, run your own storage set on this machine: `make nodes-up` (see [Optional: Local Storage Nodes](#optional-local-storage-nodes)).

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

- Rust via [rustup.rs](https://rustup.rs) (the repo pins `1.98.0` in `rust-toolchain.toml`)
- Android Studio + Android NDK `27.0.12077973` if you want Android builds
- `cargo-ndk` if you want Android native builds
- Set `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) before `make android`, `make android-libs`, or `make install`
- Xcode (macOS) and `cbindgen` (`cargo install cbindgen`) if you want the iOS app
- PostgreSQL if you want local storage nodes (`make nodes-up`) or to plug an app into DSM (`make app-dev`)

Windows:

- Use PowerShell
- Run `.\scripts\dev.ps1 setup`
- Android builds require WSL2

## Clone

```bash
git clone https://github.com/deterministicstatemachine/dsm.git
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

The app connects to the beta storage set by default. No port forwarding is required. To put it on your own local set instead, see `make phones-local` below.

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

## iOS

On macOS with Xcode:

```bash
make ios-libs          # the Rust SDK for iOS (device + Simulator) as an xcframework
make ios-frontend      # the React bundle, copied into the app
make ios-simulator     # build the app for the arm64 iOS Simulator
make ios-simulator-run # install and launch it on the booted Simulator
```

For a real iPhone or iPad, `make ios-device IOS_TEAM=<your Apple team id>` builds it signed by Xcode's automatic provisioning. The iOS app runs the same Rust SDK and the same React screens as Android.

## Bitcoin / dBTC

Bitcoin testing is signet-backed. There is no local Bitcoin node workflow in this repository.

Code: `dsm_client/deterministic_state_machine/dsm/src/bitcoin/`, `dsm/src/vault/`, and `dsm_sdk/src/handlers/bitcoin_invoke_routes.rs`.

## Optional: Local Storage Nodes

Your own storage set on this machine: the network's pinned members (`dsm-node-1` to `dsm-node-5`) as five local nodes, each the production storage node binary on its own PostgreSQL database, serving TLS from a CA of the set's own.

```bash
make nodes-up      # prepare the set the first time, then start every node (ports 8080-8084)
make nodes-status  # every node's health, over verified TLS
make nodes-down    # stop the nodes
make nodes-reset   # stop them, drop their databases, forget the set and the accounts made on it
```

PostgreSQL must run with `fsync=on` and `full_page_writes=on` (the defaults). The set is reached as `DSM_DEV_PG_URL`, by default `postgresql://$USER@localhost:5432/postgres?sslmode=disable`. Everything the set needs lives under `.dsm-dev/net/`, including the client config wallets use (`dsm_env_config.toml`, trusting `dev-ca.pem`).

Point the wallets on your phones at it (debug builds only):

```bash
make phones-local  # every adb device (via adb reverse) and every booted iOS Simulator
```

A wallet that already made its identity on another storage set keeps it there: clear the app's data first (Android: `adb shell pm clear com.dsm.wallet`, then grant its Bluetooth permissions again; iOS: delete the app and run `make ios-simulator-run`). The same holds after `make nodes-reset`: it makes a new set with a new CA, so clear the wallets and run `make phones-local` again, or they refuse every node (`invalid peer certificate`).

## Plug an App Into DSM

Your app stays what it is and gets its own DSM account; players connect their wallets to it. Sign-in, payments, items, trades and matches, with no Kotlin, Swift or Rust. Start here:

```bash
make app-dev       # your app's account on your local set (starts the set too)
make starter       # the Connect starter app on http://127.0.0.1:3000
make dev-wallet    # a player's wallet in the terminal, to test without a phone
```

The whole guide, with the TypeScript and Python clients, is [BUILDING_APPS.md](BUILDING_APPS.md).

## Troubleshooting

- `make doctor` shows what is missing before you start changing files.
- If Android build prerequisites drift, rerun `make setup`.
- If frontend assets drift, rerun `make frontend`.
- For local node issues: ensure PostgreSQL is running, then `make nodes-status`; a set whose databases predate this build's schema needs `make nodes-reset && make nodes-up`.

For deeper setup and platform-specific guidance:

- [README.md](README.md)
- `make help`
