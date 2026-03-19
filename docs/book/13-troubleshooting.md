# Chapter 13 — Troubleshooting

Consolidated troubleshooting guide covering all layers: Build, Runtime, BLE, Bitcoin, Storage, and Device.

---

## Build Issues

### Rust

**`cargo build` fails with "linker not found"**
```bash
# macOS
xcode-select --install

# Linux
sudo apt install build-essential
```

**`cargo build` fails with "protoc not found"**
```bash
# macOS
brew install protobuf

# Linux
sudo apt install protobuf-compiler
```

**`cargo build` fails with dependency errors**
```bash
rustup update stable
cargo clean
cargo build --locked --workspace --all-features
```

**`make: command not found` on Windows**

Use `.\scripts\dev.ps1` instead — the Makefile is macOS/Linux only.

**PowerShell script execution disabled**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### NDK / Android Native Libs

**cargo-ndk fails: "ANDROID_NDK_HOME not set"**

```bash
# Check it's set
echo $ANDROID_NDK_HOME

# Set it (macOS example)
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"
```

**JNI symbol count wrong (not 87+)**

```bash
nm -gU libdsm_sdk.so | grep -c Java_
# If < 87, the class name may be wrong
nm -gU libdsm_sdk.so | grep Java_ | head -5
# Should show: Java_com_dsm_wallet_bridge_UnifiedNativeApi_*
# NOT: Java_com_dsm_wallet_bridge_Unified_* (old class name)
```

If symbols show `Unified_*` instead of `UnifiedNativeApi_*`, rebuild the native libs — you're using a stale `.so`.

**Gradle uses stale native libs (`mergeDebugNativeLibs UP-TO-DATE`)**

Always clean Gradle after changing `.so` files:

```bash
cd dsm_client/android && ./gradlew clean && ./gradlew :app:assembleDebug
```

**`.so` files missing from APK**

After building with `cargo ndk`, verify files exist in both locations:

```bash
ls -la dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so
ls -la dsm_client/android/app/src/main/jniLibs/armeabi-v7a/libdsm_sdk.so
ls -la dsm_client/android/app/src/main/jniLibs/x86_64/libdsm_sdk.so
ls -la dsm_client/deterministic_state_machine/jniLibs/arm64-v8a/libdsm_sdk.so
ls -la dsm_client/deterministic_state_machine/jniLibs/armeabi-v7a/libdsm_sdk.so
ls -la dsm_client/deterministic_state_machine/jniLibs/x86_64/libdsm_sdk.so
```

### Frontend

**`npm install` fails with "Cannot read properties of null"**

The frontend package supports npm and ships a `package-lock.json`, so use:

```bash
cd dsm_client/new_frontend && npm ci
```

The repository root also includes pnpm workspace helper commands, so pnpm is optional for root-level workflows, not mandatory for the frontend app itself.

**You only need a quick onboarding validation**

Start with:

```bash
make build
make typecheck
```

`make test-frontend` is the broader Jest/UI suite, not the smallest smoke check.

**`make lint` looks green but frontend lint was skipped**

This was a stale Makefile issue. The hardened `make lint` target now runs all three checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cd dsm_client/new_frontend && npm run lint
```

**TypeScript errors after proto changes**

Regenerate proto types:
```bash
cd dsm_client/new_frontend && npm run proto:gen
```

**Webpack build fails with missing loader**
```bash
cd dsm_client/new_frontend && pnpm add -D <missing-loader>
```

---

## Runtime Issues

### Bridge / Communication

**Bridge timeout (30 seconds)**

The bridge timeout is 30000ms. If operations consistently timeout:
1. Check that the SDK bootstrapped successfully (look for `SDK_READY` in logs)
2. Verify the native `.so` was loaded: `adb logcat -s DSM:* | grep loadLibrary`
3. Ensure genesis was created: `adb logcat -s DSM:* | grep genesis`

**Envelope framing error**

Genesis responses have a `0x03` prefix byte. If you see decode errors on genesis:
- Use `decodeFramedEnvelopeV3()` not raw `Envelope.fromBinary()`
- This is implemented in `useGenesisFlow.ts`

**"SDK not ready" errors**

The `SDK_READY` atomic flag must be set before any post-bootstrap operations. Check:
1. Was `sdkBootstrap` called? (happens during app init)
2. Did bootstrap complete successfully? Check logs for errors
3. Is the device identity valid? (DBRW binding must match)

### Storage Nodes

**"Connection refused" or nodes not responding**

```bash
# Check if the local storage nodes are running
curl http://localhost:8080/api/v2/health

# Restart
cd dsm_storage_node && ./scripts/stop_dev_nodes.sh && ./start_dev_nodes.sh
```

**`make test-rust` fails in SDK integration tests that contact the default storage network**

Some SDK integration tests reach the configured storage nodes.

```bash
# Confirm the default storage network is reachable
curl -skf https://13.218.83.69:8080/api/v2/health

# If you are working offline, run narrower local coverage instead
cargo test --package dsm
cargo test --package dsm_storage_node
cargo test --package dsm_sdk --lib
```

**"Database connection failed"**

```bash
# Check PostgreSQL is running
brew services list | grep postgresql    # macOS
sudo systemctl status postgresql        # Linux

# Restart PostgreSQL
brew services restart postgresql@15     # macOS
sudo systemctl restart postgresql       # Linux

# Re-run database setup
bash scripts/setup_dev_db.sh
```

**"Port already in use"**

```bash
# Find what's using the ports
lsof -i :8080-8084

# Stop local dev nodes and clean up
cd dsm_storage_node && ./scripts/stop_dev_nodes.sh
rm -f dev-node*.pid

# Force kill if needed
pkill -f dsm_storage_node
```

**Schema drift errors ("column X does not exist")**

```bash
cd dsm_storage_node
./scripts/stop_dev_nodes.sh
./scripts/setup_dev_db.sh    # recreates databases
./start_dev_nodes.sh
```

**"role dsm does not exist"**

```bash
bash scripts/setup_dev_db.sh
# If that fails:
sudo -u postgres bash scripts/setup_dev_db.sh   # Linux
```

---

## BLE Issues

**BLE pairing doesn't complete**

1. Enable Bluetooth on both devices: `adb shell svc bluetooth enable`
2. Check app has Bluetooth permissions (Settings → Apps → DSM Wallet → Permissions)
3. Clear app data and retry: `adb shell pm clear com.dsm.wallet`
4. Check BLE discovery logs: `adb logcat -s BluetoothAdapter:* BtGatt.GattService:*`

**BLE transfer times out**

- Ensure both devices are within BLE range (< 10 meters, line of sight preferred)
- The 500ms radio transition gap is enforced by `BleCoordinator` — if you see rapid scan/advertise switches in logs, the coordinator may be overwhelmed
- Increase timeout if needed: app uses 30s default for BLE operations

**"No BLE backend" error**

The BLE backend must be registered during SDK initialization. This happens automatically on Android but may not be available on desktop builds. Check that the `bluetooth` feature flag is enabled in the build.

**Devices not discovering each other**

1. Toggle Bluetooth off/on on both devices
2. Ensure Location is enabled (Android requires location for BLE scanning)
3. Restart the app on both devices
4. Try swapping roles (advertiser ↔ scanner)

---

## Bitcoin / dBTC Issues

**App shows "mempool client init failed" or "tx_status failed"**

Check in order:
1. Is `bitcoin_network = "signet"` set in the active env config?
2. Can the device reach the internet / configured mempool backend?
3. Was the APK rebuilt after config changes? `make android`

**Integration tests fail with "connection refused"**

Tests no longer depend on a local Bitcoin Core node. Re-run the signet-oriented suite:
```bash
cargo test --package dsm_sdk --test bitcoin_tap_e2e -- --test-threads=1 --nocapture
```

**Address format wrong (`1...` or `3...` instead of `tb1q...`)**

Check that `bitcoin_network = "signet"` is set in config. Legacy addresses mean mainnet is selected.

**HTLC claim fails: "script execution failed"**

The preimage doesn't match the hashlock. Verify both sides use the same 32-byte secret:
```bash
echo -n "<hex_preimage>" | xxd -r -p | sha256sum
```

**Clean reset of Bitcoin config**

```bash
cd dsm_client/new_frontend
npm run build:android-webpack
npm run copy:android
```

---

## Device Issues

**Device not recognized by adb**

```bash
adb devices
# If "unauthorized": unlock phone and accept RSA key prompt
# If "offline": disconnect and reconnect USB cable
# If nothing shows: ensure USB debugging is enabled
```

**`adb: command not found`**

```bash
# macOS
brew install android-platform-tools

# Linux
sudo apt install adb

# Windows: download from developer.android.com/tools/releases/platform-tools
```

**App shows "connection error" on phone**

Run the `adb reverse` commands:
```bash
adb reverse tcp:8080 tcp:8080
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

**Flaky USB connection (device disconnects)**

- Try a different USB cable (prefer USB-C to USB-C)
- Try a different USB port
- Use wireless adb as an alternative:
  ```bash
  adb tcpip 5555
  adb connect <device_ip>:5555
  ```

**App crashes on launch**

Check logs for the root cause:
```bash
adb logcat -s DSM:* DsmNative:* AndroidRuntime:E | head -50
```

Common causes:
- Missing native lib → rebuild with `make android-libs`
- JNI method not found → verify symbol count (87+)
- DBRW initialization failure → clear app data and retry

**"run-as: Package is not debuggable"**

The app must be a debug build. Release builds block `run-as`. Build with:
```bash
cd dsm_client/android && ./gradlew :app:assembleDebug
```

---

## CI / Quality Issues

**CI scan finds banned patterns (TODO, FIXME, HACK, XXX)**

These are banned in production code. Search and remove:
```bash
git grep -rn "TODO\|FIXME\|HACK\|XXX"
```

**Proto guard fails**

Regenerate proto types:
```bash
cd dsm_client/new_frontend && npm run proto:gen
```

Then commit the regenerated files.

**Clippy warnings fail CI**

Fix all warnings — CI runs with `-D warnings`:
```bash
cargo clippy --all-targets -- -D warnings
```

**Format check fails**

```bash
cargo fmt --all
```

---

## Log Capture for Bug Reports

### Quick capture (one device)

```bash
adb logcat -s DSM:* DsmNative:* -d > dsm_logs.txt
```

### Live monitoring (two devices)

```bash
# Terminal 1
adb -s <DEVICE_A> logcat -s DSM:* DsmNative:* | tee device_a.log

# Terminal 2
adb -s <DEVICE_B> logcat -s DSM:* DsmNative:* | tee device_b.log
```

### Storage node logs

```bash
tail -50 dsm_storage_node/logs/dev-node1.log
```

---

Next: [Chapter 14 — Contributing](14-contributing.md)
