---
name: verify-symbols
description: Verify JNI symbol count in libdsm_sdk.so across all 3 ABIs after NDK build
disable-model-invocation: true
---

# Verify JNI Symbols

Verify that all 3 ABI builds of `libdsm_sdk.so` contain the expected number of JNI symbols (87+). Run this after any NDK build to catch symbol regressions.

## Steps

### 1. Check all 3 ABIs exist

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
for ABI in arm64-v8a armeabi-v7a x86_64; do
  SO="$REPO_ROOT/dsm_client/android/app/src/main/jniLibs/$ABI/libdsm_sdk.so"
  if [ -f "$SO" ]; then
    SIZE=$(ls -lh "$SO" | awk '{print $5}')
    MOD=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$SO")
    echo "OK: $ABI ($SIZE, modified $MOD)"
  else
    echo "MISSING: $ABI — run /ndk-build first"
  fi
done
```

### 2. Count Java_ symbols per ABI

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
EXPECTED=87
FAIL=0
for ABI in arm64-v8a armeabi-v7a x86_64; do
  SO="$REPO_ROOT/dsm_client/android/app/src/main/jniLibs/$ABI/libdsm_sdk.so"
  if [ ! -f "$SO" ]; then
    echo "SKIP: $ABI (file not found)"
    FAIL=1
    continue
  fi
  COUNT=$(nm -gU "$SO" 2>/dev/null | grep -c "Java_" || echo 0)
  if [ "$COUNT" -ge "$EXPECTED" ]; then
    echo "PASS: $ABI has $COUNT Java_ symbols (>= $EXPECTED)"
  else
    echo "FAIL: $ABI has only $COUNT Java_ symbols (expected >= $EXPECTED)"
    FAIL=1
  fi
done
if [ "$FAIL" -eq 1 ]; then
  echo ""
  echo "Symbol verification FAILED — check build output"
else
  echo ""
  echo "All ABIs verified successfully"
fi
```

### 3. Compare app-level and repo-level .so files

Verify both copy locations have identical files:

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
MISMATCH=0
for ABI in arm64-v8a armeabi-v7a x86_64; do
  APP_SO="$REPO_ROOT/dsm_client/android/app/src/main/jniLibs/$ABI/libdsm_sdk.so"
  REPO_SO="$REPO_ROOT/jniLibs/$ABI/libdsm_sdk.so"
  if [ ! -f "$APP_SO" ] || [ ! -f "$REPO_SO" ]; then
    echo "SKIP: $ABI (one or both files missing)"
    continue
  fi
  APP_HASH=$(shasum -a 256 "$APP_SO" | awk '{print $1}')
  REPO_HASH=$(shasum -a 256 "$REPO_SO" | awk '{print $1}')
  if [ "$APP_HASH" = "$REPO_HASH" ]; then
    echo "MATCH: $ABI (sha256: ${APP_HASH:0:16}...)"
  else
    echo "MISMATCH: $ABI — app and repo .so differ!"
    echo "  app:  $APP_HASH"
    echo "  repo: $REPO_HASH"
    MISMATCH=1
  fi
done
if [ "$MISMATCH" -eq 1 ]; then
  echo ""
  echo "WARNING: Mismatched .so files — run /ndk-build to sync"
fi
```

### 4. List exported JNI function names (arm64-v8a)

For reference, list all exported Java_ symbols:

```bash
REPO_ROOT=$(git rev-parse --show-toplevel)
SO="$REPO_ROOT/dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so"
if [ -f "$SO" ]; then
  echo "Exported JNI symbols:"
  nm -gU "$SO" | grep "Java_" | awk '{print $NF}' | sort
fi
```

### 5. Report summary

Print a summary with:
- Symbol count per ABI
- Whether all ABIs match expected count (87+)
- Whether app-level and repo-level .so files are in sync
- Timestamp of most recent .so build
