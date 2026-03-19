# Chapter 3 — Development Setup

Full development environment configuration for all platforms. This extends the quickstart with everything needed for active development: Android builds, multiple test devices, IDE setup, and iterative workflows.

---

## Platform Support Matrix

| Workflow | macOS | Linux | Windows | Notes |
|----------|-------|-------|---------|-------|
| Rust core / SDK work | Yes | Yes | Yes | Native on all three platforms |
| Frontend work | Yes | Yes | Yes | Node.js 20+ required |
| Local storage nodes | Yes | Yes | Yes | PostgreSQL required |
| `dsm-gen` and code generation | Yes | Yes | Yes | Cargo-based |
| Android APK build / install | Yes | Yes | WSL2 | Native Windows Android builds are not supported |
| Bash / Zsh helper scripts | Yes | Yes | WSL2 | Use PowerShell or WSL2 on Windows depending on the script |

The supported Windows story is: native Windows for most day-to-day development, WSL2 for Android builds and Unix-only helper scripts.

---

## Prerequisites Table

| Tool | Version | Required For | Install |
|------|---------|-------------|---------|
| Rust | stable | Core, SDK, storage node | [rustup.rs](https://rustup.rs) |
| cargo-ndk | latest | Android native libs | `cargo install cargo-ndk` |
| Android NDK | 27.x | JNI compilation | Android Studio SDK Manager |
| Android SDK + platform-tools | — | APK build, adb | Android Studio |
| Java | 17 | Gradle/Android build | `brew install --cask temurin@17` (macOS) |
| Node.js | 20+ | Frontend build | [nvm](https://github.com/nvm-sh/nvm) recommended |
| PostgreSQL | 15+ | Storage nodes | `brew install postgresql@15` (macOS) |
| protoc | latest | Proto generation | `brew install protobuf` (macOS) |
| adb | — | Device management | Included in Android platform-tools |

---

## macOS Setup

### 1. Install Homebrew (if needed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

### 2. Install system dependencies

```bash
brew install rustup postgresql@15 protobuf node git
brew install --cask temurin@17
brew link postgresql@15 --force
brew services start postgresql@15
```

### 3. Install Rust toolchain

```bash
rustup-init -y
source "$HOME/.cargo/env"
cargo install cargo-ndk
```

### 4. Install Android Studio and NDK

1. Download and install [Android Studio](https://developer.android.com/studio)
2. Open Android Studio → Tools → SDK Manager → SDK Tools
3. Check **NDK (Side by side)** and click OK
4. Find the installed NDK version:

```bash
ls ~/Library/Android/sdk/ndk/
# e.g.: 27.0.12077973
```

### 5. Set environment variables

Add to `~/.zshrc`:

```bash
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export JAVA_HOME="$(/usr/libexec/java_home -v 17)"
```

Reload: `source ~/.zshrc`

### 6. Clone and first-time setup

```bash
git clone https://github.com/irrefutable-labs/dsm.git
cd dsm
make doctor
make setup
```

`make doctor` reports missing prerequisites without changing the repo. `make setup` verifies the toolchain, installs frontend dependencies if needed, and generates the `.cargo/config.toml` for NDK cross-compilation when `ANDROID_NDK_HOME` is configured.

---

## Linux Setup (Ubuntu/Debian)

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y build-essential git curl postgresql postgresql-contrib \
  protobuf-compiler nodejs npm openjdk-17-jdk
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo install cargo-ndk
```

### 3. Install Android Studio and NDK

Download Android Studio from [developer.android.com](https://developer.android.com/studio). Install the NDK via SDK Manager.

Add to `~/.bashrc`:

```bash
export ANDROID_NDK_HOME="$HOME/Android/sdk/ndk/27.0.12077973"
export ANDROID_HOME="$HOME/Android/sdk"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
```

### 4. Clone and setup

```bash
git clone https://github.com/irrefutable-labs/dsm.git
cd dsm
make setup
```

---

## Windows Setup

All Rust and frontend development works natively on Windows. Android APK builds require WSL2.

### 1. Install prerequisites

| Tool | Install |
|------|---------|
| Rust | [rustup.rs](https://rustup.rs) — use `x86_64-pc-windows-msvc` toolchain |
| Node.js 20+ | [nodejs.org](https://nodejs.org) |
| PostgreSQL | [postgresql.org](https://www.postgresql.org/download/windows/) — ensure `psql` is in PATH |
| Git | [git-scm.com](https://git-scm.com) |
| protoc | `winget install Google.Protobuf` |
| PowerShell 7+ | Pre-installed on Windows 11 |

### 2. Clone and setup

```powershell
git clone https://github.com/irrefutable-labs/dsm.git
cd dsm
.\scripts\dev.ps1 setup
```

### 3. Use `scripts\dev.ps1` instead of `make`

`dev.ps1` covers the normal Windows-native development loop:

```powershell
.\scripts\dev.ps1 help          # list all targets
.\scripts\dev.ps1 menu          # interactive launcher
.\scripts\dev.ps1 build         # build Rust workspace
.\scripts\dev.ps1 nodes-up      # start storage nodes
.\scripts\dev.ps1 nodes-down    # stop storage nodes
.\scripts\dev.ps1 nodes-status  # check node health
.\scripts\dev.ps1 test          # run all tests
```

If you see a script execution error:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 4. Android builds on Windows (WSL2)

```powershell
wsl --install -d Ubuntu-24.04
```

Inside WSL2, follow the Linux setup above. Build from WSL2:

```bash
make android
```

Copy the APK from WSL2 to Windows to sideload, or use `make install` if the device is connected via USB.

### 5. Unix-only helper scripts on Windows

These helpers are currently documented as Unix-only and should be run from WSL2 rather than native PowerShell:

- Root shell helpers in `scripts/`, such as `fast_deploy_android.sh`, `adb_reverse_storage.sh`, `push_env_override.sh`, and `rebind_recipient_device.sh`
- Android client shell helpers in `dsm_client/scripts/`, such as `android_device_test.sh`, `analyze_device_logs.sh`, and `auto-bridge-complete.sh`
- Storage node shell helpers in `dsm_storage_node/scripts/`
- Storage deployment automation in `dsm_storage_node/deploy/`

Portable exceptions:

- `scripts/dev.ps1` is the native Windows entry point
- `scripts/aggregate_coverage.mjs` is Node-based
- The Python helpers in `dsm_client/scripts/` are not shell-specific, though they may still assume local toolchain prerequisites

---

## `.cargo/config.toml` Template

After running `make setup`, the file `dsm_client/deterministic_state_machine/dsm_sdk/.cargo/config.toml` is generated from the template using your `ANDROID_NDK_HOME`. It configures the NDK linkers for all three Android targets:

- `aarch64-linux-android` (arm64-v8a)
- `armv7-linux-androideabi` (armeabi-v7a)
- `x86_64-linux-android` (x86_64)

If you need to regenerate it, delete the file and re-run `make setup`.

---

## Directory Structure

```
dsm/
├── Makefile                              — all developer tasks (macOS/Linux)
├── scripts/dev.ps1                       — primary Windows-native developer entry point
├── CLAUDE.md                             — project conventions and invariants
├── proto/dsm_app.proto                   — canonical protobuf definitions
├── dsm-gen/                              — specification-driven code generator for DLV and policy clients
├── dsm_client/
│   ├── android/                          — Android app (Kotlin + JNI + WebView)
│   │   ├── app/src/main/
│   │   │   ├── java/com/dsm/wallet/     — Kotlin source
│   │   │   ├── jniLibs/                  — native .so files (3 ABIs)
│   │   │   └── assets/                   — frontend bundle + config
│   │   └── build.gradle.kts
│   ├── new_frontend/                     — React 18 frontend (TypeScript)
│   │   ├── src/
│   │   │   ├── App.tsx                   — custom router, screen rendering
│   │   │   ├── bridge/                   — MessagePort binary bridge
│   │   │   ├── contexts/                 — WalletContext, BleContext, etc.
│   │   │   ├── dsm/                      — WebViewBridge, EventBridge
│   │   │   ├── hooks/                    — useGenesisFlow, etc.
│   │   │   ├── proto/                    — generated protobuf types
│   │   │   └── services/                 — dsmClient API
│   │   └── package.json
│   └── deterministic_state_machine/
│       ├── dsm/src/                      — core protocol crate (pure Rust)
│       │   ├── core/                     — state machine, bilateral
│       │   ├── crypto/                   — BLAKE3, SPHINCS+, ML-KEM, DBRW
│       │   ├── vault/                    — DLV, limbo vaults
│       │   └── cpta/                     — token policy anchors
│       └── dsm_sdk/src/                  — JNI-exposed SDK crate
│           ├── jni/                      — JNI dispatch, bootstrap
│           ├── bluetooth/                — BLE handler, frame coordinator
│           ├── sdk/                      — bilateral, token, DLV, Bitcoin APIs
│           └── security/                 — DBRW validation
├── dsm_storage_node/                     — storage node binary (Rust + Axum)
│   ├── src/
│   ├── scripts/                          — local multi-node dev management
│   ├── deploy/                           — AWS deployment scripts
│   └── terraform/                        — infrastructure as code
├── scripts/                              — build, CI, and automation scripts
├── tools/                                — E2E test automation (Python)
├── ci/                                   — CI gate scripts
└── docs/                                 — documentation
    └── book/                             — this handbook
```

---

## Iterative Development Workflows

### Changed only Rust code

```bash
make android-libs                        # rebuild .so files only (~2 min)
cd dsm_client/android && ./gradlew clean :app:installDebug   # reinstall
```

`make android-libs` mirrors `libdsm_sdk.so` into both authoritative locations:

- `dsm_client/android/app/src/main/jniLibs/`
- `dsm_client/deterministic_state_machine/jniLibs/`

This keeps the packaged APK path and the Rust-side mirror in sync.

### Changed only frontend code

```bash
make frontend                            # rebuild JS bundle (~15 sec)
cd dsm_client/android && ./gradlew :app:installDebug
```

### Fastest iteration (push existing APK)

```bash
make install-only                        # no rebuild, just install
```

### Regenerate protobuf types

After editing `proto/dsm_app.proto`:

```bash
cd dsm_client/new_frontend && npm run proto:gen
```

This regenerates `src/proto/dsm_app_pb.ts`. Never use inline type casts or duck-typed interfaces — always regenerate.

---

## Environment Configuration

### How Config Reaches the Device

```
android/app/src/main/assets/dsm_env_config.toml
  │
  │  APK build bundles this into assets/
  │
  ▼
MainActivity.materializeEnvConfig()
  │
  │  ALWAYS overwrites /data/user/0/com.dsm.wallet/files/dsm_env_config.toml
  │  from the bundled asset on every app start (no "already exists" check)
  │
  ▼
/data/user/0/com.dsm.wallet/files/dsm_env_config.toml
  │
  │  Rust SDK reads this path via ENV_CONFIG_PATH global
  │
  ▼
dsm_sdk::network::NetworkConfigLoader
  │
  │  Checks allow_localhost field in TOML
  │  If false/missing: rejects all 127.0.0.1 endpoints
  │
  ▼
Genesis success or failure
```

### The Three TOML Source Files

| File | Purpose | Authoritative? |
|------|---------|----------------|
| `new_frontend/public/dsm_env_config.toml` | Frontend dev server, reference config | YES — keep this one up to date |
| `android/app/src/main/assets/dsm_env_config.toml` | Bundled into APK, materialized to device | MUST match the public version |
| `new_frontend/android-assets/dsm_env_config.toml` | Legacy copy location (may not exist) | Deprecated, ignore |

**Rule: When you change the public TOML, also update the Android assets TOML.**

### Default Config (AWS Production Nodes)

The shipped config connects to 6 production AWS storage nodes over HTTPS:

```toml
protocol = "https"
lan_ip   = "0.0.0.0"
allow_localhost = false
storage_node_mode = "remote"
ports    = [8080]

bitcoin_network = "signet"
custom_ca_certs = ["ca.crt"]

[[nodes]]
name     = "us-east-1a"
endpoint = "https://13.218.83.69:8080"

[[nodes]]
name     = "us-east-1b"
endpoint = "https://44.223.31.184:8080"

# ... 4 more nodes across eu-west-1 and ap-southeast-1
```

With outbound internet access, no local PostgreSQL or port forwarding is required. The default config can connect directly to the AWS nodes.

### Localhost Override (Optional Local Dev)

For offline development with local storage nodes, push a localhost override:

```bash
scripts/push_env_override.sh --local
```

This pushes a config with `allow_localhost = true` and `http://127.0.0.1:808x` endpoints. You also need to forward ports:

```bash
adb reverse tcp:8080 tcp:8080
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

### LAN Testing (Two Devices on Wi-Fi, No USB)

```toml
lan_ip = "192.168.x.x"    # your computer's LAN IP
[[nodes]]
endpoint = "http://192.168.x.x:8080"
# ...
```

Do **not** commit a modified config with a real LAN IP.

### Override Mechanism (Hot-Fix Without APK Rebuild)

`materializeEnvConfig()` checks for override files **before** copying from assets:

1. `files/dsm_env_config.override.toml` (highest priority)
2. `files/dsm_env_config.local.toml`
3. External files dir `dsm_env_config.toml`
4. Downloads dir `dsm_env_config.toml`

To hot-fix a running device without rebuilding the APK:

```bash
# Push the correct config as an override
adb push new_frontend/public/dsm_env_config.toml /data/local/tmp/dsm_env_config.override.toml
adb shell run-as com.dsm.wallet cp /data/local/tmp/dsm_env_config.override.toml files/dsm_env_config.override.toml

# Force-stop and restart
adb shell am force-stop com.dsm.wallet
adb shell am start -n com.dsm.wallet/.ui.MainActivity
```

The override persists across app restarts and takes priority over the bundled asset.

To remove the override (after deploying a fixed APK):

```bash
adb shell run-as com.dsm.wallet rm files/dsm_env_config.override.toml
```

### Diagnosing Config Issues

If genesis fails with:
```
STRICT: env config unavailable or contains no storage nodes.
Discovery is disabled in production builds.
```

**Possible causes:**
1. **No internet** — the default config points to AWS nodes over HTTPS. Ensure the device has internet access.
2. **Localhost override active but no local nodes** — if you previously pushed a localhost override, the app tries `127.0.0.1` endpoints. Remove the override: `adb shell run-as com.dsm.wallet rm files/dsm_env_config.override.toml`
3. **Missing `allow_localhost`** — only relevant when using local dev nodes. The production config correctly sets `allow_localhost = false`.

Verify the on-device config:
```bash
adb shell run-as com.dsm.wallet cat files/dsm_env_config.toml
```

### Checklist After Modifying Config

- Updated `new_frontend/public/dsm_env_config.toml`
- Updated `android/app/src/main/assets/dsm_env_config.toml` to match
- Rebuilt APK (`./gradlew clean && ./gradlew :app:assembleDebug`)
- Or pushed override to device for immediate testing

---

## 16 KB Page Size Support

Android devices with larger RAM are adopting 16 KB memory page sizes. DSM supports this with the necessary manifest properties and native library build flags.

### What Changed

1. **AndroidManifest.xml** — declares explicit support:
   ```xml
   <property android:name="android.supports_16kb_page_size" android:value="true" />
   ```

2. **Rust linker flags** — `dsm_sdk/.cargo/config.toml` includes for all Android targets:
   ```toml
   "-C", "link-arg=-Wl,-z,max-page-size=16384"  # 16 KB page alignment
   ```

The 16 KB alignment is backward compatible with 4 KB devices.

### Testing on 16 KB Emulator

```bash
# Create AVD with Android 15 "16 KB" system image
# Select Pixel 8, API 35, x86_64 or arm64-v8a

# Verify page size
adb shell getconf PAGE_SIZE
# Should output: 16384

# Build and install normally
make android && make install-only
```

### Testing Checklist

- App launches without crashes
- Genesis wallet creation completes
- BLE pairing and bilateral transfers work
- Camera QR scanning works
- Storage-node sync works
- App survives background/foreground transitions

### Debugging 16 KB Issues

```bash
# Check native library alignment (look for Align 0x4000 or higher)
readelf -l dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep LOAD

# Check for SIGBUS or alignment errors
adb logcat | grep -E "SIGBUS|alignment|page.?size"

# Rebuild with verbose linker output
RUSTFLAGS="-C link-arg=-Wl,--verbose" cargo ndk ...
```

---

## IDE Recommendations

### Rust (VS Code)

- Install `rust-analyzer` extension
- Set `rust-analyzer.cargo.features = "all"` for full feature coverage
- Use `cargo clippy --all-targets` for lint integration

### TypeScript (VS Code)

- Install `ESLint` and `Prettier` extensions
- The frontend uses webpack, not Vite — dev server runs via `npm run dev`

### Kotlin (Android Studio)

- Open `dsm_client/android/` as the project root
- Use JDK 17 (File → Project Structure → SDK)

---

## Connecting Test Devices

### Enable Developer Mode

1. Settings → About Phone → tap **Build Number** 7 times
2. Settings → Developer Options → enable **USB Debugging**

### Connect via USB

```bash
adb devices                              # verify device shows as "device"
adb reverse tcp:8080 tcp:8080            # forward storage node ports
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

### Two-device setup (for BLE testing)

```bash
# Get both device serials
adb devices

# Forward ports on both devices
adb -s <SERIAL_A> reverse tcp:8080 tcp:8080
# ... repeat for all ports and both devices
```

See [Chapter 9 — BLE Testing](09-ble-testing.md) for the full BLE test workflow.

---

Next: [Chapter 4 — Architecture](04-architecture.md)
