# Set up your machine

The tools are the usual ones: Git, a C toolchain, protobuf's compiler, Node.js 20 or later, Python 3 for the Python client, and Rust. A JDK 17 is for building the Android wallet. PostgreSQL is not on the list: you need it only if you later run storage nodes of your own.

## 1. Install the prerequisites

**macOS**, with [Homebrew](https://brew.sh). The second line, the JDK, is only for building the Android wallet.

```bash
brew install git protobuf node
brew install --cask temurin@17
```

macOS already has Python 3 with `venv`.

**Ubuntu or Debian.** Ubuntu's own `nodejs` package is older than the Node.js 20 this repo needs, so Node comes from NodeSource:

```bash
sudo apt update
sudo apt install -y build-essential git curl protobuf-compiler openjdk-17-jdk python3-venv
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

These four lines are the ones the newcomer check (`make first-run`) runs on a clean Ubuntu before it follows this path to a payment received.

## 2. Install Rust

Rust comes from [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then open a new terminal, or load it into this one:

```bash
. "$HOME/.cargo/env"
```

The repo pins the Rust version it builds with (`1.98.0`, in `rust-toolchain.toml`). rustup installs it the first time you build in the repo.

## 3. Get the code

```bash
git clone https://github.com/deterministicstatemachine/dsm.git
cd dsm
```

Every command from here on runs in this folder.

## 4. Check the machine

```bash
make doctor
```

Doctor reads every tool the build needs and says what it found. It changes nothing on your machine. If a tool the build needs is missing, the line says `MISSING` and doctor fails. Tools you need only for the wallet's builds (`adb`, `java`, `cargo-ndk`) are marked optional until you build it.

It prints something like this. Yours will differ:

```text
==> DSM doctor
    cargo: cargo 1.98.0 (797e8a9bc 2026-08-05)
    rustc: rustc 1.98.0 (88d9e12ae 2026-08-18)
    rust toolchain pin: 1.98.0 (rust-toolchain.toml)
    rustfmt: installed
    clippy: installed
    protoc: libprotoc 33.4
    node: v20.19.5
    npm: 10.8.2
    bash: version 5 (OK)
    adb: available
    psql: available
    java: openjdk version "24" 2025-03-18
    cargo-ndk: cargo-ndk 4.1.2
    …
    frontend deps: stale (package-lock.json changed since they were installed; run make setup)
    …
==> every prerequisite is here
```

The lines marked `…` are the Android NDK's, with paths on the machine that recorded this. `frontend deps: stale` is about the wallet's own web code, below.

## 5. For the wallet's builds only

Plugging an app in needs nothing more. To build the wallet yourself ([next page](wallet.md)), install its web code's dependencies, and with the Android NDK set up, its Android build config:

```bash
make setup
```

`make setup` works before any Android tooling is installed; it writes the Android config only when `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) is set.

Next: [The wallet on Android and iOS](wallet.md), or skip straight to [your app's own DSM account](account.md).
