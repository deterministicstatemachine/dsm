---
name: ndk-build
description: Full NDK rebuild pipeline - TS frontend build, cargo ndk build all 3 arches, copy .so files, gradle clean + assembleDebug, install on connected devices
disable-model-invocation: true
---

# NDK Build & Deploy

Run the full TypeScript frontend build → Rust NDK cross-compilation → Gradle APK → device install pipeline.

## Steps

Execute these steps **in order**, stopping on any failure. Steps 1-2 (TS frontend) and step 3 (delete stale .so) can run in parallel since they are independent.

### 1. Build TypeScript frontend

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/new_frontend && \
npm run build:full-deploy
```

This runs type-check → lint → webpack production build → copy assets to Android `assets/` directory. **Stop on errors** (lint warnings are OK).

### 2. Delete stale `.so` files (can run parallel with step 1)

```bash
rm -f /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so \
     /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs/armeabi-v7a/libdsm_sdk.so \
     /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs/x86_64/libdsm_sdk.so
```

### 3. Cargo NDK build (all 3 architectures)

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs \
  --platform 23 build --release --package dsm_sdk --features=jni,bluetooth
```

This is a long build (~5-10 min). Use a generous timeout.

### 4. Copy `.so` to repo-level jniLibs

Copy from cargo target directories to the repo-level `jniLibs/` directory:

```bash
cp /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine/target/aarch64-linux-android/release/libdsm_sdk.so \
   /Users/cryptskii/Desktop/claude_workspace/dsm/jniLibs/arm64-v8a/libdsm_sdk.so

cp /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine/target/armv7-linux-androideabi/release/libdsm_sdk.so \
   /Users/cryptskii/Desktop/claude_workspace/dsm/jniLibs/armeabi-v7a/libdsm_sdk.so

cp /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine/target/x86_64-linux-android/release/libdsm_sdk.so \
   /Users/cryptskii/Desktop/claude_workspace/dsm/jniLibs/x86_64/libdsm_sdk.so
```

### 5. Verify JNI symbols

```bash
nm -gU /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep -c Java_
```

**Expected**: 87+ symbols. If fewer, the build may have failed silently. Report the count.

### 6. Gradle clean + assembleDebug

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android && \
./gradlew clean && \
./gradlew :app:assembleDebug --no-daemon --console=plain
```

**CRITICAL**: The `clean` step is mandatory — Gradle caches stale `.so` files in `mergeDebugNativeLibs`.

### 7. Install on connected devices

Detect connected devices and install the APK on each:

```bash
APK="/Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
for DEVICE in $(adb devices | awk '/\tdevice$/{print $1}'); do
  echo "Installing on $DEVICE..."
  adb -s "$DEVICE" install -r "$APK"
done
```

### 8. Set up ADB reverse port forwarding

Forward storage node ports on each device:

```bash
for DEVICE in $(adb devices | awk '/\tdevice$/{print $1}'); do
  for PORT in 8080 8081 8082 8083 8084; do
    adb -s "$DEVICE" reverse tcp:$PORT tcp:$PORT
  done
  echo "Port forwarding set for $DEVICE"
done
```

### 9. Report summary

Print a summary including:
- TS frontend build result (errors/warnings from step 1)
- JNI symbol count (from step 5)
- APK file size
- Devices installed on
- Any warnings or errors encountered
