#!/usr/bin/env zsh
# Re-bind recipient device inbox and ensure local storage node connectivity
# - Clears app data to regenerate genesis
# - Installs debug APK if needed
# - Reverses ports 8080-8084
# - Pushes env override to app-private storage (STRICT mode)
# - Starts app and tails logs for readiness
#
# Usage:
#   scripts/rebind_recipient_device.sh -s <SERIAL> [-p <APK_PATH>] [-e <ENV_PATH>] [--no-build]
#
# Defaults:
#   APK_PATH = dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
#   ENV_PATH = dsm_client/new_frontend/public/dsm_env_config.toml
#
set -euo pipefail

function usage() {
  echo "Usage: $0 -s <SERIAL> [-p <APK_PATH>] [-e <ENV_PATH>] [--no-build]"
  echo "  -s SERIAL    Recipient device adb serial (required)"
  echo "  -p APK_PATH  Path to APK (default: dsm_client/android/app/build/outputs/apk/debug/app-debug.apk)"
  echo "  -e ENV_PATH  Path to env config TOML to push (default: dsm_client/new_frontend/public/dsm_env_config.toml)"
  echo "  --no-build   Do not build APK if not found"
}

SERIAL=""
APK="dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
ENV_FILE="dsm_client/new_frontend/public/dsm_env_config.toml"
NO_BUILD=0

# Parse args
while (( $# > 0 )); do
  case "$1" in
    -s) SERIAL="$2"; shift 2 ;;
    -p) APK="$2"; shift 2 ;;
    -e) ENV_FILE="$2"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$SERIAL" ]]; then
  echo "Error: -s <SERIAL> is required."
  usage
  exit 2
fi

# Verify adb
if ! command -v adb >/dev/null 2>&1; then
  echo "Error: adb not found in PATH"
  exit 3
fi

# Verify device is connected
if ! adb devices | awk '/\tdevice$/{print $1}' | grep -qx "$SERIAL"; then
  echo "Error: device $SERIAL is not connected in 'device' state"
  adb devices -l
  exit 4
fi

# Build APK if missing
if [[ ! -f "$APK" ]]; then
  if (( NO_BUILD )); then
    echo "Error: APK not found and --no-build specified: $APK"
    exit 5
  fi
  echo "APK not found; building debug APK..."
  (cd dsm_client/android && ./gradlew :app:assembleDebug --no-daemon --console=plain) || { echo "Gradle build failed"; exit 6; }
fi

# Install or reinstall APK
echo "=== Installing APK to $SERIAL ==="
adb -s "$SERIAL" uninstall com.dsm.wallet || true
adb -s "$SERIAL" install -r "$APK"

# Clear app data to force fresh genesis
echo "=== Clearing app data (fresh genesis) ==="
adb -s "$SERIAL" shell pm clear com.dsm.wallet || true

# Reverse storage ports
for p in 8080 8081 8082 8083 8084; do
  echo "Reverse tcp:$p on $SERIAL"
  adb -s "$SERIAL" reverse tcp:$p tcp:$p || echo "reverse failed for $SERIAL:$p"
done

# Push env override to app-private storage
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: env file not found: $ENV_FILE"
  exit 7
fi
TMP_REMOTE="/data/local/tmp/dsm_env_config.override.toml"
echo "=== Pushing env override from $ENV_FILE to $SERIAL:$TMP_REMOTE ==="
adb -s "$SERIAL" push "$ENV_FILE" "$TMP_REMOTE"

echo "=== Installing env override into app-private storage ==="
adb -s "$SERIAL" shell run-as com.dsm.wallet mkdir -p files
adb -s "$SERIAL" shell run-as com.dsm.wallet cp /data/local/tmp/dsm_env_config.override.toml files/dsm_env_config.override.toml
adb -s "$SERIAL" shell run-as com.dsm.wallet ls -l files/dsm_env_config.override.toml

# Start the app
echo "=== Starting app ==="
adb -s "$SERIAL" shell am start -n com.dsm.wallet/.ui.MainActivity || echo "Failed to start app on $SERIAL"

# Short log confirmation
echo "=== Tail recent logs for identity readiness and balance refresh ==="
sleep 3
adb -s "$SERIAL" logcat -d | grep -E '(WalletContext: initialize|needs_genesis|wallet_ready|dsm-identity-ready|dsm-balances-updated|syncWithStorage)' | tail -50 || true

echo "=== Re-bind completed for $SERIAL ==="
