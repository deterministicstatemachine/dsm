#!/usr/bin/env zsh
# Auto-start DSM Wallet with BLE advertising + scanning on all connected devices.
# Requires debug build with DEV_AUTOBROADCAST support (added in MainActivity).
# Usage: ./scripts/android_auto_ble.sh

set -euo pipefail
APK="dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK" ]; then
  echo "[auto-ble] APK not found; building..." >&2
  (cd dsm_client/android && ./gradlew :app:assembleDebug --no-daemon --console=plain)
fi
SERIALS=($(adb devices | awk '/\tdevice$/{print $1}'))
if [ ${#SERIALS[@]} -eq 0 ]; then
  echo "[auto-ble] No devices connected." >&2
  exit 2
fi
for d in ${SERIALS[@]}; do
  echo "[auto-ble] === $d ==="
  adb -s "$d" install -r "$APK" >/dev/null || { echo "[auto-ble] install failed on $d"; continue; }
  # Launch with auto_ble extra (inline automation) then send broadcast after small delay in case of race
  adb -s "$d" shell am start -n com.dsm.wallet/.ui.MainActivity --ez auto_ble true >/dev/null || echo "[auto-ble] launch failed on $d"
  sleep 2
  adb -s "$d" shell am broadcast -a com.dsm.wallet.DEV_AUTOBROADCAST >/dev/null || echo "[auto-ble] broadcast failed on $d"
  # Reverse storage ports if helpful for offline/online hybrid flows
  for p in 8080 8081 8082 8083 8084; do
    adb -s "$d" reverse tcp:$p tcp:$p >/dev/null || echo "[auto-ble] reverse failed $d:$p"
  done
  # Pull last 20 lines containing automation markers
  echo "[auto-ble] recent automation logs:";
  adb -s "$d" logcat -d | grep -E 'DEV_AUTOBROADCAST|startBleAutomation' | tail -n 20 || true
  echo "[auto-ble] === done $d ==="
  echo
done
