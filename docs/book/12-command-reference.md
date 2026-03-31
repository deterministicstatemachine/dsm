# Chapter 12 — Command Reference

Every `make` target, `npm` script, shell script, and PowerShell equivalent.

---

## Makefile Targets (macOS/Linux)

Run from the repository root. `make help` lists all targets, `make menu` opens an interactive launcher, and `make doctor` checks prerequisites without changing files.

### Setup

| Target | Description |
|--------|-------------|
| `make menu` | Interactive launcher for the most common tasks |
| `make doctor` | Read-only prerequisite check for cargo, node, npm, protoc, adb, PostgreSQL, Java, and Android NDK state |
| `make setup` | First-time onboarding: check prerequisites, install frontend dependencies, generate `.cargo/config.toml` when the Android NDK is configured |
| `make help` | List all available targets |

### Build

| Target | Description |
|--------|-------------|
| `make build` | Build full Rust workspace (`cargo build --locked --workspace --all-features`) |
| `make build-release` | Build Rust workspace in release mode |
| `make android-libs` | Build native `.so` libs for all 3 Android ABIs (arm64-v8a, armeabi-v7a, x86_64) |
| `make frontend` | Build React frontend (copies assets into Android) |
| `make android` | Full debug APK: native libs + frontend + Gradle assemble |
| `make android-release` | Full release APK |

### Install

| Target | Description |
|--------|-------------|
| `make install` | Build debug APK and install on all connected adb devices |
| `make install-only` | Install existing APK without rebuilding (fastest iteration) |

### Test

| Target | Description |
|--------|-------------|
| `make test` | Run the full Rust workspace + frontend Jest suites (broader than the onboarding smoke check) |
| `make test-rust` | Rust tests only, including broader SDK integration coverage |
| `make test-frontend` | Frontend Jest suite (broader than `make typecheck`) |
| `make typecheck` | TypeScript type-check only |

`make typecheck` is the fastest supported frontend validation. The `make test*` targets are fuller development suites rather than the initial onboarding smoke check.

### Lint / Quality

| Target | Description |
|--------|-------------|
| `make lint` | Run all linters: `cargo fmt --check`, `cargo clippy`, frontend lint |
| `make fmt` | Auto-format Rust code (`cargo fmt --all`) |
| `make audit` | Security audit: `cargo-audit` + `cargo-deny` |
| `make deny` | Run `cargo-deny` license/advisory check |

### Storage Nodes

| Target | Description |
|--------|-------------|
| `make nodes-up` | Set up the dev database and start the 5 local storage nodes |
| `make nodes-down` | Stop the local storage dev nodes |
| `make nodes-status` | Check local storage node health and port status |
| `make nodes-reset` | Stop local nodes and clean pid/log state |

### CI / Proto

| Target | Description |
|--------|-------------|
| `make proto-guard` | Verify protobuf sources are in sync |
| `make ci-scan` | Run all CI gate scripts (flow assertions, symbol checks) |
| `make flow-assertions` | Run flow assertion checks |
| `make flow-mapping-assertions` | Run flow mapping assertion checks |

### Clean

| Target | Description |
|--------|-------------|
| `make clean` | Remove all build artifacts (Rust, frontend, Gradle) |

---

## PowerShell Targets (Windows)

Run from the repository root using `.\scripts\dev.ps1`.

| Target | Description |
|--------|-------------|
| `.\scripts\dev.ps1 help` | List all available targets |
| `.\scripts\dev.ps1 menu` | Interactive launcher |
| `.\scripts\dev.ps1 setup` | Check prerequisites |
| `.\scripts\dev.ps1 doctor` | Alias of `setup` |
| `.\scripts\dev.ps1 build` | Build Rust workspace |
| `.\scripts\dev.ps1 test` | Run all tests |
| `.\scripts\dev.ps1 nodes-up` | Set up database + start storage nodes |
| `.\scripts\dev.ps1 nodes-down` | Stop the local storage nodes |
| `.\scripts\dev.ps1 nodes-status` | Check local storage node health |

---

## Platform Notes

- `make` is the primary entry point on macOS and Linux.
- `.\scripts\dev.ps1` is the primary entry point on Windows.
- Android APK builds are supported on macOS and Linux directly, and on Windows through WSL2.
- Most `.sh` and `.zsh` helper scripts in this repository are Unix-only unless explicitly noted otherwise.
- Node-based helpers such as `scripts/aggregate_coverage.mjs` and Python helpers such as `dsm_client/scripts/generate-kotlin-jni.py` are not shell-specific, but still depend on local toolchain availability.

### Unix-only Helper Surfaces

These are currently documented as macOS/Linux/WSL2 helpers, not native Windows commands:

- `scripts/*.sh` and `scripts/*.zsh`
- `dsm_client/scripts/*.sh`
- `dsm_storage_node/scripts/*.sh`
- `dsm_storage_node/deploy/*.sh`

Notable examples:

- `scripts/fast_deploy_android.sh`
- `scripts/adb_reverse_storage.sh`
- `scripts/rebind_recipient_device.sh`
- `dsm_client/scripts/android_device_test.sh`
- `dsm_storage_node/deploy/provision_aws.sh`

---

## npm Scripts (Frontend)

Run from `dsm_client/frontend/`.

| Script | Description |
|--------|-------------|
| `npm run build` | Production webpack build |
| `npm run build:full-deploy` | Type-check → lint → webpack → copy to Android assets |
| `npm run dev` | Webpack dev server (hot reload) |
| `npm run type-check` | TypeScript type-check (`tsc --noEmit`) |
| `npm run lint` | ESLint check |
| `npm run lint:fix` | ESLint auto-fix |
| `npm test` | Jest test suite |
| `npm test -- --watch` | Jest in watch mode |
| `npm run proto:gen` | Regenerate TypeScript protobuf types from `proto/dsm_app.proto` |

---

## Rust Test Commands

### Core tests

```bash
# All workspace tests
cargo test --workspace --all-features

# Core crate only
cargo test --package dsm

# SDK crate only
cargo test --package dsm_sdk

# Storage node only
cargo test --package dsm_storage_node

# Specific test
cargo test --package dsm --lib -- test_name
```

### Bitcoin integration tests

See [Chapter 8](08-bitcoin-dbtc.md) for the signet-backed flow.

```bash
# Bitcoin E2E tests
cargo test --package dsm_sdk --test bitcoin_tap_e2e -- --test-threads=1 --nocapture

# Unit tests (no node required)
cargo test --package dsm_sdk --lib -- bitcoin
```

### Android tests

```bash
# JUnit + Robolectric
cd dsm_client/android && ./gradlew :app:testDebugUnitTest

# On-device instrumented tests
cd dsm_client/android && ./gradlew :app:connectedDebugAndroidTest
```

---

## `dsm-gen`

Run from the repository root:

```bash
# Show all commands and flags
cargo run -p dsm-gen -- --help

# Validate a vault or policy specification
cargo run -p dsm-gen -- validate path/to/spec.yaml

# Generate typed clients
cargo run -p dsm-gen -- client path/to/spec.yaml --lang ts
cargo run -p dsm-gen -- --output-dir ./generated client path/to/spec.yaml --lang kotlin,swift

# Export JSON schema for tooling or CI
cargo run -p dsm-gen -- schema vault --output ./vault-schema.json
cargo run -p dsm-gen -- schema policy --output ./policy-schema.json

# Scaffold a new spec-first project
cargo run -p dsm-gen -- init my-dsm-project
```

See [Chapter 16 — Code Generation](16-code-generation.md) for workflows and examples.

---

## Shell Scripts

The maintained shell surface is intentionally limited. If a task is not listed here, treat `make` or `.\scripts\dev.ps1` as the supported entry point instead of looking for older ad hoc helpers at the repository root.

### Storage Nodes (`dsm_storage_node/`)

| Script | Usage | Description |
|--------|-------|-------------|
| `setup_dev_db.sh` | `bash scripts/setup_dev_db.sh` | Create dev PostgreSQL databases (one-time) |
| `start_dev_nodes.sh` | `cd dsm_storage_node && ./start_dev_nodes.sh` | Start 5 local storage nodes (ports 8080-8084) |
| `stop_dev_nodes.sh` | `./scripts/stop_dev_nodes.sh` | Stop all local dev nodes |
| `check_node_status.sh` | `./scripts/check_node_status.sh` | Check port usage and `/api/v2/health` status for all local nodes |
| `dev_nodes_reset.sh` | `bash scripts/dev_nodes_reset.sh [--start]` | Stop local nodes, clean logs/pids, optionally relaunch |

### Bitcoin Signet

The app now uses signet through the configured mempool backend. There are no local Bitcoin helper scripts.

### CI / Quality (`scripts/`)

| Script | Usage | Description |
|--------|-------|-------------|
| `ci_scan.sh` | `bash scripts/ci_scan.sh` | Run all CI gate scans |
| `flow_assertions.sh` | `bash scripts/flow_assertions.sh` | Verify flow assertions |
| `flow_mapping_assertions.sh` | `bash scripts/flow_mapping_assertions.sh` | Verify flow mapping assertions |
| `guard_protos.sh` | `bash scripts/guard_protos.sh` | Check protobuf sync |
| `codegen_enforce.sh` | `bash scripts/codegen_enforce.sh` | Enforce codegen rules |

### Build / Install (`scripts/`)

| Script | Usage | Description |
|--------|-------|-------------|
| `install_apk_connected_devices.sh` | (called by `make install`) | Install APK on all connected adb devices |
| `push_env_override.sh` | `bash scripts/push_env_override.sh` | Push env config to connected devices |

### AWS Deployment (`dsm_storage_node/deploy/`)

| Script | Usage | Description |
|--------|-------|-------------|
| `provision_aws.sh` | `bash deploy/provision_aws.sh --ssh-key <key>` | Full AWS deploy (Terraform + Docker + push) |
| `generate_node_configs.sh` | (called by provision) | Generate per-node TLS certs + configs |
| `push_and_start.sh` | (called by provision) | Docker build + push + start on nodes |
| `check_nodes.sh` | `bash deploy/check_nodes.sh <IPs>` | Health check all cloud nodes |
| `teardown_aws.sh` | `bash deploy/teardown_aws.sh --ssh-key <key>` | Destroy all AWS resources |

---

## E2E Test Scripts (Python)

Run from the repository root. Requires Python 3.9+ and two connected Android devices.

| Script | Usage | Description |
|--------|-------|-------------|
| `tools/ble_pairing_e2e.py` | `python3 tools/ble_pairing_e2e.py --device1 <s1> --device2 <s2>` | Automate BLE pairing |
| `tools/offline_send_e2e.py` | `python3 tools/offline_send_e2e.py --device1 <s1> --device2 <s2>` | Automate offline bilateral transfer |
| `tools/verify_persistence.py` | `python3 tools/verify_persistence.py --device1 <s1> --device2 <s2>` | Verify on-device SQLite persistence |
| `tools/live_smoke_orchestrator.py` | `python3 tools/live_smoke_orchestrator.py --device1 <s1> --device2 <s2>` | Full smoke test (pairing + persistence) |
| `tools/adb_utils.py` | (library) | Core ADB utilities, UI automation |

---

## adb Commands

### Port Forwarding (storage nodes)

```bash
adb reverse tcp:8080 tcp:8080
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

### Multi-device

```bash
# List connected devices
adb devices

# Target specific device
adb -s <SERIAL> reverse tcp:8080 tcp:8080
adb -s <SERIAL> install -r path/to/app-debug.apk
```

### Log Monitoring

```bash
# DSM-specific logs
adb logcat -s DSM:* DsmNative:*

# BLE-specific logs
adb logcat -s BluetoothAdapter:* BtGatt.GattService:*

# Save to file
adb logcat -s DSM:* DsmNative:* | tee dsm_logs.txt
```

### App Management

```bash
# Clear app data
adb shell pm clear com.dsm.wallet

# Force stop
adb shell am force-stop com.dsm.wallet

# Launch app
adb shell am start -n com.dsm.wallet/.ui.MainActivity

# Launch with auto BLE test
adb shell am start -n com.dsm.wallet/.ui.MainActivity --ez auto_ble true
```

### Push Config

```bash
adb push dsm_env_config.toml /data/local/tmp/
adb shell run-as com.dsm.wallet cp /data/local/tmp/dsm_env_config.toml files/
```

---

## JNI Symbol Verification

After building native libs, verify the JNI symbol count:

```bash
# Check arm64 (primary)
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep -c Java_
# Expected: 87+

# Check all ABIs match
for abi in arm64-v8a armeabi-v7a x86_64; do
  count=$(nm -gU dsm_client/android/app/src/main/jniLibs/$abi/libdsm_sdk.so | grep -c Java_)
  echo "$abi: $count symbols"
done
```

---

## Health Checks

### Storage Nodes

```bash
# Single node
curl http://localhost:8080/api/v2/health

# All 5 nodes
for port in 8080 8081 8082 8083 8084; do
  curl -s http://localhost:$port/api/v2/health | grep -q ok \
    && echo "Node $port: OK" \
    || echo "Node $port: NOT RUNNING"
done
```

### Bitcoin Signet

```bash
rg "bitcoin_network" dsm_client/frontend/public/dsm_env_config.toml
# Shows: chain height, wallet balance, recent transactions
```

---

Next: [Chapter 13 — Troubleshooting](13-troubleshooting.md)
